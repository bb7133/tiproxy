#!/usr/bin/env bash
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Minimal pure-Rust single-process MIG-01: a persistent client on the main
# --standalone entry (FAULT_PORT) is atomically migrated A0 -> A1 by swapping
# the PD-etcd /config/proxy fail-list, with current database and a user
# variable preserved. Reuses the T3 local-migration mechanism (t3_set_route_policy
# + FIFO client) but drops the Go-bridge dropper/ForceClose extensions. No Go
# tiproxy is launched (this runs before the keyspace-guard sub-phase).
run_standalone_mig01() {
	[[ -n $etcdctl_bin && -x $etcdctl_bin ]] || { echo "standalone MIG-01 needs etcdctl" >&2; exit 1; }
	command -v jq >/dev/null 2>&1 || { echo "standalone MIG-01 needs jq" >&2; exit 1; }
	sa_set_route_policy() {
		local failed=$1 timeout=$2 phase=$3 current value
		current=$(ETCDCTL_API=3 "$etcdctl_bin" --endpoints "http://127.0.0.1:$PD_PORT" \
			get /config/proxy --print-value-only)
		if [[ -z $current ]]; then
			current=$(jq -cn \
				--arg pd_a "127.0.0.1:$PD_PORT" --arg pd_b "127.0.0.1:$PD_PORT_B" \
				--arg proxy_protocol "$dynamic_proxy_protocol" '{
					"max-connections":100,"high-memory-usage-reject-threshold":0.9,"conn-buffer-size":32768,
					"frontend-keepalive":{"enabled":true,"idle":0,"cnt":0,"intvl":0,"timeout":0},
					"backend-healthy-keepalive":{"enabled":true,"idle":60000000000,"cnt":5,"intvl":3000000000,"timeout":15000000000},
					"backend-unhealthy-keepalive":{"enabled":true,"idle":10000000000,"cnt":5,"intvl":1000000000,"timeout":5000000000},
					"proxy-protocol":$proxy_protocol,"graceful-wait-before-shutdown":0,"graceful-close-conn-timeout":5,
					"public-endpoints":[],
					"backend-clusters":[{"name":"cluster-a","pd-addrs":$pd_a,"ns-servers":[]},{"name":"cluster-b","pd-addrs":$pd_b,"ns-servers":[]}],
					"fail-backend-list":[],"failover-timeout":60}')
		fi
		value=$(jq -c --argjson failed "$failed" --argjson timeout "$timeout" \
			'.["fail-backend-list"]=$failed | .["failover-timeout"]=$timeout' <<<"$current")
		printf '%s\n' "$value" >"$run_dir/sa-mig-$phase.json"
		ETCDCTL_API=3 "$etcdctl_bin" --endpoints "http://127.0.0.1:$PD_PORT" \
			put /config/proxy "$value" >"$run_dir/sa-mig-etcd-$phase.log"
	}
	sa_mig_query() {
		local marker=$1 sql=$2 line=
		printf '%s\n' "$sql" >&8
		for _ in {1..60}; do
			line=$(grep -s "^$marker|" "$run_dir/sa-mig-session.out" | tail -1 || true)
			[[ -n $line ]] && { printf '%s\n' "$line"; return 0; }
			kill -0 "$MIG_SESSION_PID" 2>/dev/null || { echo "standalone MIG-01 session exited before $marker" >&2; tail -8 "$run_dir/sa-mig-session.out" >&2 || true; return 1; }
			sleep 0.25
		done
		echo "standalone MIG-01 session never answered $marker" >&2; return 1
	}
	local p= streak=0 pin_ready=false
	sa_set_route_policy "[\"127.0.0.1:$TIDB_PORT_1\",\"127.0.0.1:$TIDB_PORT_B\"]" 300 pin
	for _ in {1..80}; do
		p=$(mysql_ingress 'SELECT @@port' 2>/dev/null || true)
		if [[ $p == "$TIDB_PORT_0" ]]; then streak=$((streak+1)); ((streak>=5)) && { pin_ready=true; break; }; else streak=0; fi
		sleep 0.25
	done
	[[ $pin_ready == true ]] || { echo "standalone MIG-01: A0 pin did not absorb (landed '$p')" >&2; exit 1; }
	mysql --batch --skip-column-names --connect-timeout=2 -h 127.0.0.1 -P "$TIDB_PORT_0" -u root --ssl-mode=DISABLED -e 'CREATE DATABASE IF NOT EXISTS sa_mig;'
	MIG_FIFO="$run_dir/sa-mig-session.fifo"; mkfifo "$MIG_FIFO"
	local rust_offset; rust_offset=$(wc -l <"$run_dir/tiproxy-rs.log" | tr -d ' ')
	mysql --batch --skip-column-names --skip-reconnect --unbuffered \
		-h 127.0.0.1 -P "$FAULT_PORT" -u root \
		"${mysql_tls_args[@]}" ${mysql_compression_arg:+"$mysql_compression_arg"} \
		<"$MIG_FIFO" >"$run_dir/sa-mig-session.out" 2>&1 &
	MIG_SESSION_PID=$!; write_state; exec 8>"$MIG_FIFO"
	local baseline
	baseline=$(sa_mig_query SABASE "USE sa_mig; SET @m='state-live'; BEGIN; SELECT CONCAT('SABASE|', CONNECTION_ID(), '|', @@port, '|', COALESCE(DATABASE(),'NULL'), '|', COALESCE(@m,'NULL'));") || exit 1
	[[ $(cut -d'|' -f3 <<<"$baseline") == "$TIDB_PORT_0" && $(cut -d'|' -f4 <<<"$baseline") == sa_mig && $(cut -d'|' -f5 <<<"$baseline") == state-live ]] || { echo "standalone MIG-01 invalid baseline: $baseline" >&2; exit 1; }
	local conn_id=
	for _ in {1..30}; do conn_id=$(tail -n "+$((rust_offset+1))" "$run_dir/tiproxy-rs.log" | grep '"event":"connection_ready"' | head -1 | sed -n 's/.*"connection_id":\([0-9]*\).*/\1/p'); [[ -n $conn_id ]] && break; sleep 0.25; done
	[[ -n $conn_id ]] || { echo "standalone MIG-01 could not identify the persistent Rust session" >&2; exit 1; }
	local streak2=0 swap_ready=false
	sa_set_route_policy "[\"127.0.0.1:$TIDB_PORT_0\",\"127.0.0.1:$TIDB_PORT_B\"]" 300 swap
	for _ in {1..80}; do
		p=$(mysql_ingress 'SELECT @@port' 2>/dev/null || true)
		if [[ $p == "$TIDB_PORT_1" ]]; then streak2=$((streak2+1)); ((streak2>=5)) && { swap_ready=true; break; }; else streak2=0; fi
		sleep 0.25
	done
	[[ $swap_ready == true ]] || { echo "standalone MIG-01: A1 swap did not absorb (landed '$p')" >&2; exit 1; }
	sa_mig_query SACOMMIT "COMMIT; SELECT CONCAT('SACOMMIT|', CONNECTION_ID(), '|', @@port);" >/dev/null || exit 1
	local migrated=false row= rport= rdb= rmk=
	for a in {1..60}; do
		row=$(sa_mig_query "SATRY$a" "SELECT CONCAT('SATRY$a|', CONNECTION_ID(), '|', @@port, '|', COALESCE(DATABASE(),'NULL'), '|', COALESCE(@m,'NULL'));") || exit 1
		rport=$(cut -d'|' -f3 <<<"$row"); rdb=$(cut -d'|' -f4 <<<"$row"); rmk=$(cut -d'|' -f5 <<<"$row")
		[[ $rport == "$TIDB_PORT_1" ]] && { migrated=true; break; }
		sleep 0.25
	done
	[[ $migrated == true && $rdb == sa_mig && $rmk == state-live ]] || { echo "standalone MIG-01 failed or lost session state: ${row:-<none>}" >&2; exit 1; }
	kill -0 "$MIG_SESSION_PID" 2>/dev/null || { echo "standalone MIG-01 client died instead of surviving the swap" >&2; exit 1; }
	exec 8>&-; wait "$MIG_SESSION_PID" 2>/dev/null || true; rm -f "$MIG_FIFO"; MIG_SESSION_PID=; MIG_FIFO=; write_state
	echo "standalone MIG-01 live migration: conn_id=$conn_id A0=$TIDB_PORT_0 -> A1=$TIDB_PORT_1; database+user-variable restored ($row)"
}
