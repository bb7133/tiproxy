#!/usr/bin/env bash
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Run a second pure Rust process with both keyspaces in one MatchAll group.
# The main standalone process uses port routing and cannot exercise this case.
run_standalone_cross_keyspace() {
	local ka_sql_port=$((8097 + port_offset))
	local ka_api_port=$((8098 + port_offset))
	local ka_health_port=$((8099 + port_offset))
	local ka_fault_port=$((8103 + port_offset))
	local ka_fault_admin_port=$((8104 + port_offset))
	KA_FAULT_PORT=$ka_fault_port
	local port
	for port in "$ka_sql_port" "$ka_api_port" "$ka_health_port" "$ka_fault_port" "$ka_fault_admin_port"; do
		if "$FAULT_PROXY_BIN" --probe "127.0.0.1:$port" >/dev/null 2>&1; then
			echo "standalone cross-keyspace port already in use: $port" >&2
			exit 1
		fi
	done
	PORTS="$PORTS $ka_sql_port $ka_api_port $ka_health_port $ka_fault_port $ka_fault_admin_port"
	write_state
	python3 - "$run_dir/tiproxy.toml" "$run_dir/tiproxy-ka.toml" \
		"$TIPROXY_PORT" "$TIPROXY_API_PORT" "$ka_sql_port" "$ka_api_port" \
		"$run_dir" "$TIDB_PORT_1" "$TIDB_PORT_B" <<'PYKA'
import sys

source, target, main_sql, main_api, sql, api, run_dir, a1, b = sys.argv[1:]
text = open(source).read().split("\n[rust-dataplane]", 1)[0]
def once(old, new):
    global text
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"standalone MatchAll config: {old!r} occurs {count} times")
    text = text.replace(old, new)
once(f'addr = "127.0.0.1:{main_sql}"', f'addr = "127.0.0.1:{sql}"')
once(f'addr = "127.0.0.1:{main_api}"', f'addr = "127.0.0.1:{api}"')
once('port-range = [' + main_sql + ', ' + str(int(main_sql) + 1) + ']\n', '')
once('routing-rule = "port"\n', '')
once(f'workdir = "{run_dir}/tiproxy-work"', f'workdir = "{run_dir}/standalone-ka-workdir"')
once(f'filename = "{run_dir}/tiproxy.log"', f'filename = "{run_dir}/standalone-ka.log"')
once('graceful-wait-before-shutdown = 0',
     'graceful-wait-before-shutdown = 0\n'
     f'fail-backend-list = ["127.0.0.1:{a1}", "127.0.0.1:{b}"]\n'
     'failover-timeout = 300')
text += '\n[rust-dataplane]\nenabled = true\n'
open(target, 'w').write(text)
PYKA
	sa_set_route_policy "[\"127.0.0.1:$TIDB_PORT_1\",\"127.0.0.1:$TIDB_PORT_B\"]" 300 cross-pin
	local tls_args=()
	if [[ $TLS_ENABLED == true ]]; then
		tls_args=(--tls-root "$run_dir/certs")
	fi
	"$rust_binary" --config "$run_dir/tiproxy-ka.toml" --standalone \
		--health-port "$ka_health_port" ${tls_args[@]+"${tls_args[@]}"} \
		>"$run_dir/standalone-ka.out" 2>&1 &
	KA_PID=$!
	write_state
	local ready=false
	for _ in {1..150}; do
		kill -0 "$KA_PID" 2>/dev/null || break
		if curl --noproxy '*' --fail --silent --max-time 5 \
			"http://127.0.0.1:$ka_health_port/health" \
			-o "$run_dir/standalone-ka-ready.json"; then
			ready=true
			break
		fi
		sleep 0.2
	done
	[[ $ready == true ]] || {
		echo "standalone MatchAll Rust process never became ready" >&2
		tail -30 "$run_dir/standalone-ka.out" >&2 || true
		exit 1
	}
	local fault_args=(--listen "127.0.0.1:$ka_fault_port"
		--admin "127.0.0.1:$ka_fault_admin_port"
		--target "127.0.0.1:$ka_sql_port")
	if [[ $PROXY_ENABLED == true ]]; then
		fault_args+=(--proxy-v2)
	fi
	"$FAULT_PROXY_BIN" "${fault_args[@]}" >"$run_dir/standalone-ka-faultproxy.log" 2>&1 &
	KA_FAULT_PID=$!
	write_state
	local mysql_args=(--batch --skip-column-names --skip-reconnect
		-h 127.0.0.1 -P "$ka_fault_port" -u root)
	mysql_args+=(${mysql_tls_args[@]+"${mysql_tls_args[@]}"})
	if [[ -n ${mysql_compression_arg:-} ]]; then
		mysql_args+=("$mysql_compression_arg")
	fi
	local p= pin_ready=false
	for _ in {1..80}; do
		p=$(mysql "${mysql_args[@]}" -e 'SELECT @@port' 2>/dev/null || true)
		[[ $p == "$TIDB_PORT_0" ]] && { pin_ready=true; break; }
		sleep 0.25
	done
	[[ $pin_ready == true ]] || { echo "standalone MatchAll A0 pin not ready: $p" >&2; exit 1; }
	mysql --batch --skip-column-names --ssl-mode=DISABLED \
		-h 127.0.0.1 -P "$TIDB_PORT_0" -u root \
		-e 'CREATE DATABASE IF NOT EXISTS sa_cross;'
	KA_FIFO="$run_dir/standalone-ka-session.fifo"
	mkfifo "$KA_FIFO"
	mysql "${mysql_args[@]}" --force --unbuffered \
		<"$KA_FIFO" >"$run_dir/standalone-ka-session.out" 2>&1 &
	KA_SESSION_PID=$!
	write_state
	exec 9>"$KA_FIFO"
	sa_ka_query() {
		local marker=$1 sql=$2 row=
		printf '%s\n' "$sql" >&9
		for _ in {1..60}; do
			row=$(grep -s "^$marker|" "$run_dir/standalone-ka-session.out" | tail -1 || true)
			[[ -n $row ]] && { printf '%s\n' "$row"; return 0; }
			kill -0 "$KA_SESSION_PID" 2>/dev/null || {
				echo "standalone MatchAll session died before $marker" >&2
				tail -8 "$run_dir/standalone-ka-session.out" >&2 || true
				return 1
			}
			sleep 0.25
		done
		echo "standalone MatchAll session did not answer $marker" >&2
		return 1
	}
	local baseline
	baseline=$(sa_ka_query SABASE "USE sa_cross; SET @sa_cross='alive'; SELECT CONCAT('SABASE|', CONNECTION_ID(), '|', @@port, '|', COALESCE(DATABASE(),'NULL'), '|', COALESCE(@sa_cross,'NULL'));") || exit 1
	[[ $(cut -d'|' -f3 <<<"$baseline") == "$TIDB_PORT_0" &&
		$(cut -d'|' -f4 <<<"$baseline") == sa_cross &&
		$(cut -d'|' -f5 <<<"$baseline") == alive ]] || {
		echo "standalone MatchAll baseline invalid: $baseline" >&2
		exit 1
	}
	# The native API must self-migrate this exact session within ks-old.
	curl --noproxy '*' --fail --silent --show-error --max-time 5 \
		"http://127.0.0.1:$ka_api_port/api/admin/namespace/" \
		-o "$run_dir/standalone-ka-namespaces.json"
	curl --noproxy '*' --fail --silent --show-error --max-time 5 \
		"http://127.0.0.1:$ka_api_port/api/backend/metrics?cluster=cluster-a" \
		-o "$run_dir/standalone-ka-backend-metrics.json"
	local redirect_code
	redirect_code=$(curl --noproxy '*' --silent --show-error --max-time 5 \
		-X POST "http://127.0.0.1:$ka_api_port/api/debug/redirect" \
		-o "$run_dir/standalone-ka-redirect.json" -w '%{http_code}')
	[[ $redirect_code == 200 ]] || {
		echo "standalone CP-ADMIN redirect returned $redirect_code" >&2
		exit 1
	}
	local before_conn after_conn admin_row= admin_ok=false
	before_conn=$(cut -d'|' -f2 <<<"$baseline")
	for attempt in {1..60}; do
		admin_row=$(sa_ka_query "SAADM$attempt" "SELECT CONCAT('SAADM$attempt|', CONNECTION_ID(), '|', @@port, '|', COALESCE(DATABASE(),'NULL'), '|', COALESCE(@sa_cross,'NULL'));" ) || exit 1
		after_conn=$(cut -d'|' -f2 <<<"$admin_row")
		if [[ $after_conn != "$before_conn" &&
			$(cut -d'|' -f3 <<<"$admin_row") == "$TIDB_PORT_0" &&
			$(cut -d'|' -f4 <<<"$admin_row") == sa_cross &&
			$(cut -d'|' -f5 <<<"$admin_row") == alive ]]; then
			admin_ok=true
			break
		fi
		sleep 0.25
	done
	[[ $admin_ok == true ]] || {
		echo "standalone CP-ADMIN did not self-migrate: $baseline -> $admin_row" >&2
		exit 1
	}
	curl --noproxy '*' --fail --silent --show-error --max-time 5 \
		"http://127.0.0.1:$ka_health_port/health" \
		-o "$run_dir/standalone-ka-before-cross-health.json"
	local baseline_refusals
	baseline_refusals=$(jq -r '.route_ledger.keyspace_refusals' \
		"$run_dir/standalone-ka-before-cross-health.json")
	[[ $baseline_refusals =~ ^[0-9]+$ ]] || {
		echo "standalone cross-keyspace refusal baseline missing" >&2
		exit 1
	}
	# A new connection must select ks-new after the swap. The old live
	# session must retain its exact ks-old backend identity.
	sa_set_route_policy "[\"127.0.0.1:$TIDB_PORT_0\",\"127.0.0.1:$TIDB_PORT_1\"]" 300 cross-swap
	local swap_ready=false
	for _ in {1..80}; do
		p=$(mysql "${mysql_args[@]}" -e 'SELECT @@port' 2>/dev/null || true)
		[[ $p == "$TIDB_PORT_B" ]] && { swap_ready=true; break; }
		sleep 0.25
	done
	[[ $swap_ready == true ]] || { echo "standalone cross-keyspace swap not absorbed: $p" >&2; exit 1; }
	# A stable old session alone could pass if no redirect was ever offered.
	# Require the Rust router's own bounded refusal counter to advance.
	local refusals=0
	for _ in {1..80}; do
		curl --noproxy '*' --fail --silent --show-error --max-time 5 \
			"http://127.0.0.1:$ka_health_port/health" \
			-o "$run_dir/standalone-ka-cross-health.json"
		refusals=$(jq -r '.route_ledger.keyspace_refusals // 0' \
			"$run_dir/standalone-ka-cross-health.json")
		((refusals > baseline_refusals)) && break
		sleep 0.25
	done
	((refusals > baseline_refusals)) || {
		echo "standalone cross-keyspace swap never offered a guarded redirect" >&2
		exit 1
	}
	local check
	check=$(sa_ka_query SACHK "SELECT CONCAT('SACHK|', CONNECTION_ID(), '|', @@port, '|', COALESCE(DATABASE(),'NULL'), '|', COALESCE(@sa_cross,'NULL'));" ) || exit 1
	[[ $(cut -d'|' -f2 <<<"$check") == "$after_conn" &&
		$(cut -d'|' -f3 <<<"$check") == "$TIDB_PORT_0" &&
		$(cut -d'|' -f4 <<<"$check") == sa_cross &&
		$(cut -d'|' -f5 <<<"$check") == alive ]] || {
		echo "standalone cross-keyspace guard changed old session: $admin_row -> $check" >&2
		exit 1
	}
	jq -e --argjson baseline "$baseline_refusals" '.route_ledger.active >= 1 and
		.route_ledger.keyspace_refusals > $baseline and
		.route_ledger.incoming == 0 and
		.route_ledger.outgoing == 0 and
		.route_ledger.unsettled_redirects == 0 and
		.route_ledger.unsettled_closes == 0' \
		"$run_dir/standalone-ka-cross-health.json" >/dev/null || {
		echo "standalone cross-keyspace guard left route tokens unsettled" >&2
		exit 1
	}
	sa_set_route_policy "[\"127.0.0.1:$TIDB_PORT_1\",\"127.0.0.1:$TIDB_PORT_B\"]" 300 cross-restore
	exec 9>&-
	wait "$KA_SESSION_PID" 2>/dev/null || true
	KA_SESSION_PID=
	rm -f "$KA_FIFO"
	KA_FIFO=
	write_state
	echo "PASS: standalone Rust CP-ADMIN self-migration ($baseline -> $admin_row); MatchAll cross-keyspace refusal (old=$check, new ks-new port=$p), route ledger settled, no Go tiproxy"
}
