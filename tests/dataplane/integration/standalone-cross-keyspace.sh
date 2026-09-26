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
	sa_ka_metric_count() {
		local phase=$1 health=$2 result=$3 path="$run_dir/standalone-ka-metrics-$1.txt"
		curl --noproxy '*' --fail --silent --show-error --max-time 5 \
			"http://127.0.0.1:$ka_api_port/metrics" -o "$path" || return 1
		python3 - "$path" "127.0.0.1:$TIDB_PORT_0" "$health" "$result" <<'PYMETRIC'
import re
import sys

path, backend, health, result = sys.argv[1:]
total = 0
for line in open(path):
    if not line.startswith('tiproxy_backend_keepalive_update_total{'):
        continue
    labels, value = line.split('}', 1)
    found = dict(re.findall(r'([a-z_]+)="([^"]*)"', labels))
    if (found.get('backend'), found.get('health'), found.get('result')) == (backend, health, result):
        total += int(float(value.strip()))
print(total)
PYMETRIC
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
	# KA-002 in the same 0-Go process: a stopped TiDB still holds the
	# established SQL socket but makes /status fail. Require the Rust owner
	# to apply the unhealthy policy to that exact backend. The route owner
	# may then migrate the client to healthy A1; that is a valid result, so
	# this row checks frontend-session continuity after A0 resumes rather
	# than inventing a same-backend healthy recovery. The existing Linux
	# socket-policy test reads back the exact TCP options.
	local ka_tidb_pid ka_tidb_cmd before_unhealthy now_unhealthy ka_row ka_result ka_recovered
	# The Go policy's TCP_USER_TIMEOUT option is Linux-only. On macOS the
	# engine still observes each live health transition, but reports a
	# failed setsockopt instead of silently claiming the policy was applied.
	ka_result=succeed
	[[ $(uname -s) == Linux ]] || ka_result=fail
	ka_tidb_pid=$(lsof -ti "tcp:$TIDB_PORT_0" -sTCP:LISTEN 2>/dev/null || true)
	[[ $ka_tidb_pid =~ ^[0-9]+$ ]] || {
		echo "standalone KA requires one A0 LISTEN owner, got '$ka_tidb_pid'" >&2
		exit 1
	}
	ka_tidb_cmd=$(ps -p "$ka_tidb_pid" -o command= 2>/dev/null || true)
	[[ $ka_tidb_cmd == *"/$tag/"* ]] || {
		echo "refusing KA SIGSTOP for non-run PID $ka_tidb_pid: $ka_tidb_cmd" >&2
		exit 1
	}
	before_unhealthy=$(sa_ka_metric_count before-stop unhealthy "$ka_result") || exit 1
	(
		sleep 90
		[[ $(ps -p "$ka_tidb_pid" -o command= 2>/dev/null || true) == *"/$tag/"* ]] &&
			kill -CONT "$ka_tidb_pid" 2>/dev/null || true
	) &
	KA_RESUME_WATCHDOG_PID=$!
	kill -STOP "$ka_tidb_pid" || exit 1
	KA_STOPPED_TIDB_PID=$ka_tidb_pid
	local ka_unhealthy_seen=false
	for _ in {1..60}; do
		now_unhealthy=$(sa_ka_metric_count stopped unhealthy "$ka_result") || exit 1
		if ((now_unhealthy > before_unhealthy)); then
			ka_unhealthy_seen=true
			break
		fi
		sleep 0.5
	done
	[[ $ka_unhealthy_seen == true ]] || {
		echo "standalone KA did not report unhealthy backend result=$ka_result while A0 was stopped" >&2
		exit 1
	}
	kill -CONT "$ka_tidb_pid" || exit 1
	KA_STOPPED_TIDB_PID=
	kill "$KA_RESUME_WATCHDOG_PID" 2>/dev/null || true
	wait "$KA_RESUME_WATCHDOG_PID" 2>/dev/null || true
	KA_RESUME_WATCHDOG_PID=
	ka_recovered=false
	for _ in {1..60}; do
		if curl --noproxy '*' --fail --silent --max-time 2 \
			"http://127.0.0.1:$((10080 + port_offset))/status" -o /dev/null; then
			ka_recovered=true
			break
		fi
		sleep 0.5
	done
	[[ $ka_recovered == true ]] || {
		echo "standalone KA A0 status did not recover after SIGCONT" >&2
		exit 1
	}
	ka_row=$(sa_ka_query SAKA "SELECT CONCAT('SAKA|', CONNECTION_ID(), '|', @@port, '|', COALESCE(DATABASE(),'NULL'), '|', COALESCE(@sa_cross,'NULL'));") || exit 1
	[[ ($(cut -d'|' -f3 <<<"$ka_row") == "$TIDB_PORT_0" ||
		$(cut -d'|' -f3 <<<"$ka_row") == "$TIDB_PORT_1") &&
		$(cut -d'|' -f4 <<<"$ka_row") == sa_cross &&
		$(cut -d'|' -f5 <<<"$ka_row") == alive ]] || {
		echo "standalone KA health flip lost same-client SQL state: $check -> $ka_row" >&2
		exit 1
	}
	kill -0 "$KA_SESSION_PID" 2>/dev/null || {
		echo "standalone KA client exited after health flip" >&2
		exit 1
	}
	if [[ $standalone_restart == 1 ]]; then
		run_standalone_restart "$ka_sql_port" "$ka_health_port"
	fi
	exec 9>&-
	if [[ -n ${KA_SESSION_PID:-} ]]; then
		wait "$KA_SESSION_PID" 2>/dev/null || true
		KA_SESSION_PID=
		rm -f "$KA_FIFO"
		KA_FIFO=
		write_state
	fi
	echo "PASS: standalone Rust CP-ADMIN self-migration ($baseline -> $admin_row); MatchAll cross-keyspace refusal (old=$check, new ks-new port=$p), route ledger settled; KA-002 A0 unhealthy policy result=$ka_result count $before_unhealthy->$now_unhealthy with same frontend session state $ka_row after recovery; no Go tiproxy"
	if [[ $ka_result == fail ]]; then
		echo "NOTE: non-Linux KA-002 proves health delivery only; TCP_USER_TIMEOUT policy application requires the Linux result=succeed run"
	fi
}

# A gated crash-recovery check on the same second Rust instance. The old
# frontend connection must break on SIGKILL; recovery is proved by a NEW
# client that can route and migrate after the process rebinds its listeners.
run_standalone_restart() {
	local ka_sql_port=$1 ka_health_port=$2
	local old_pid=$KA_PID old_client=$KA_SESSION_PID old_conn pre_row new_pid= old_output_line=
	local ready=false listener_pid= old_disconnected=false process_state=
	local p= streak=0 pin_ready=false baseline= baseline_conn= row= migrated=false
	local ingress_ready=false swap_streak=0
	local tls_args=()
	if [[ $TLS_ENABLED == true ]]; then
		tls_args=(--tls-root "$run_dir/certs")
	fi
	local mysql_args=(--batch --skip-column-names --skip-reconnect
		-h 127.0.0.1 -P "$KA_FAULT_PORT" -u root)
	mysql_args+=(${mysql_tls_args[@]+"${mysql_tls_args[@]}"})
	if [[ -n ${mysql_compression_arg:-} ]]; then
		mysql_args+=("$mysql_compression_arg")
	fi
	pre_row=$(sa_ka_query SROLDPRE "SET @sa_restart='pre'; SELECT CONCAT('SROLDPRE|', CONNECTION_ID(), '|', @@port, '|', COALESCE(DATABASE(),'NULL'), '|', COALESCE(@sa_restart,'NULL'));") || exit 1
	[[ $(cut -d'|' -f4 <<<"$pre_row") == sa_cross &&
		$(cut -d'|' -f5 <<<"$pre_row") == pre ]] || {
		echo "standalone restart old-client baseline invalid: $pre_row" >&2
		exit 1
	}
	old_conn=$(cut -d'|' -f2 <<<"$pre_row")
	old_output_line=$(wc -l <"$run_dir/standalone-ka-session.out" | tr -d ' ')
	assert_standalone_no_go restart-before
	curl --noproxy '*' --fail --silent --show-error --max-time 5 \
		"http://127.0.0.1:$ka_health_port/health" \
		-o "$run_dir/standalone-restart-before-health.json"
	sigkill_owned_process "$old_pid" "$run_dir/tiproxy-ka.toml" || exit 1
	wait "$old_pid" 2>/dev/null || true
	KA_PID=
	write_state
	if kill -0 "$old_pid" 2>/dev/null; then
		echo "standalone restart old Rust PID $old_pid survived SIGKILL" >&2
		exit 1
	fi
	# Probe the same --skip-reconnect client before opening any replacement.
	# A successful row would mean the old session survived the crash falsely.
	(printf '%s\n' "SELECT CONCAT('SROLD|', CONNECTION_ID());" >&9) 2>/dev/null || true
	for _ in {1..60}; do
		if tail -n "+$((old_output_line + 1))" "$run_dir/standalone-ka-session.out" | grep -q '^SROLD|'; then
			echo "standalone restart old session unexpectedly answered after SIGKILL" >&2
			exit 1
		fi
		process_state=$(ps -p "$old_client" -o state= 2>/dev/null || true)
		if [[ -z $process_state || $process_state == Z* ]] ||
			tail -n "+$((old_output_line + 1))" "$run_dir/standalone-ka-session.out" |
			grep -Eq 'ERROR [0-9]+|Lost connection|server has gone away'; then
			old_disconnected=true
			break
		fi
		sleep 0.25
	done
	[[ $old_disconnected == true ]] || {
		echo "standalone restart old persistent client did not observe a disconnect" >&2
		exit 1
	}
	exec 9>&-
	# mysql --force may remain in its input loop after reporting the expected
	# connection error. It no longer represents a live server session.
	process_state=$(ps -p "$old_client" -o state= 2>/dev/null || true)
	if [[ -n $process_state && $process_state != Z* ]]; then
		kill "$old_client" 2>/dev/null || true
	fi
	for _ in {1..40}; do
		process_state=$(ps -p "$old_client" -o state= 2>/dev/null || true)
		[[ -z $process_state || $process_state == Z* ]] && break
		sleep 0.25
	done
	[[ -z $process_state || $process_state == Z* ]] || kill -KILL "$old_client" 2>/dev/null || true
	wait "$old_client" 2>/dev/null || true
	KA_SESSION_PID=
	rm -f "$KA_FIFO"
	KA_FIFO=
	write_state
	# Restore A0 pin before restart; the new owner must load and apply the
	# persisted file/etcd/topology inputs, not inherit in-memory router state.
	sa_set_route_policy "[\"127.0.0.1:$TIDB_PORT_1\",\"127.0.0.1:$TIDB_PORT_B\"]" 300 restart-pin
	"$rust_binary" --config "$run_dir/tiproxy-ka.toml" --standalone \
		--health-port "$ka_health_port" ${tls_args[@]+"${tls_args[@]}"} \
		>"$run_dir/standalone-ka-restart.out" 2>&1 &
	KA_PID=$!
	new_pid=$KA_PID
	write_state
	[[ $new_pid != "$old_pid" ]] || {
		echo "standalone restart reused old PID $old_pid" >&2
		exit 1
	}
	for _ in {1..180}; do
		kill -0 "$new_pid" 2>/dev/null || {
			echo "standalone restart Rust process exited before health readiness" >&2
			tail -30 "$run_dir/standalone-ka-restart.out" >&2 || true
			exit 1
		}
		if curl --noproxy '*' --fail --silent --max-time 2 \
			"http://127.0.0.1:$ka_health_port/health" \
			-o "$run_dir/standalone-restart-ready.json" &&
			jq -e '.status == "OK"' "$run_dir/standalone-restart-ready.json" >/dev/null; then
			ready=true
			break
		fi
		sleep 1
	done
	[[ $ready == true ]] || { echo "standalone restart did not become healthy" >&2; exit 1; }
	listener_pid=$(lsof -ti "tcp:$ka_sql_port" -sTCP:LISTEN 2>/dev/null || true)
	[[ $listener_pid == "$new_pid" ]] || {
		echo "standalone restart SQL listener owner is '$listener_pid', expected new Rust PID $new_pid" >&2
		exit 1
	}
	assert_standalone_no_go restart-after
	for _ in {1..80}; do
		p=$(mysql "${mysql_args[@]}" -e 'SELECT @@port' 2>/dev/null || true)
		if [[ $p == "$TIDB_PORT_0" ]]; then
			streak=$((streak + 1))
			((streak >= 5)) && { pin_ready=true; break; }
		else
			streak=0
		fi
		sleep 0.25
	done
	[[ $pin_ready == true ]] || {
		echo "standalone restart A0 route did not recover: $p" >&2
		exit 1
	}
	KA_FIFO="$run_dir/standalone-restart-session.fifo"
	mkfifo "$KA_FIFO"
	mysql "${mysql_args[@]}" --force --unbuffered \
		<"$KA_FIFO" >"$run_dir/standalone-restart-session.out" 2>&1 &
	KA_SESSION_PID=$!
	write_state
	exec 10>"$KA_FIFO"
	sa_restart_query() {
		local marker=$1 sql=$2 answer=
		printf '%s\n' "$sql" >&10
		for _ in {1..60}; do
			answer=$(grep -s "^$marker|" "$run_dir/standalone-restart-session.out" | tail -1 || true)
			[[ -n $answer ]] && { printf '%s\n' "$answer"; return 0; }
			kill -0 "$KA_SESSION_PID" 2>/dev/null || {
				echo "standalone restart client exited before $marker" >&2
				tail -8 "$run_dir/standalone-restart-session.out" >&2 || true
				return 1
			}
			sleep 0.25
		done
		echo "standalone restart client did not answer $marker" >&2
		return 1
	}
	baseline=$(sa_restart_query SRBASE "USE sa_cross; SET @sa_restart='post'; BEGIN; SELECT CONCAT('SRBASE|', CONNECTION_ID(), '|', @@port, '|', COALESCE(DATABASE(),'NULL'), '|', COALESCE(@sa_restart,'NULL'));") || exit 1
	baseline_conn=$(cut -d'|' -f2 <<<"$baseline")
	[[ $baseline_conn != "$old_conn" &&
		$(cut -d'|' -f3 <<<"$baseline") == "$TIDB_PORT_0" &&
		$(cut -d'|' -f4 <<<"$baseline") == sa_cross &&
		$(cut -d'|' -f5 <<<"$baseline") == post ]] || {
		echo "standalone restart new-client A0 baseline invalid: old=$pre_row new=$baseline" >&2
		exit 1
	}
	if ! grep -F '"event":"connection_ready"' "$run_dir/standalone-ka-restart.out" |
		grep -F "\"listener\":\"127.0.0.1:$ka_sql_port\"" |
		grep -F '"cluster":"cluster-a"' >/dev/null; then
		echo "standalone restart new Rust process did not record a cluster-A SQL connection" >&2
		exit 1
	fi
	sa_set_route_policy "[\"127.0.0.1:$TIDB_PORT_0\",\"127.0.0.1:$TIDB_PORT_B\"]" 300 restart-swap
	for _ in {1..80}; do
		p=$(mysql "${mysql_args[@]}" -e 'SELECT @@port' 2>/dev/null || true)
		if [[ $p == "$TIDB_PORT_1" ]]; then
			swap_streak=$((swap_streak + 1))
			((swap_streak >= 5)) && { ingress_ready=true; break; }
		else
			swap_streak=0
		fi
		sleep 0.25
	done
	[[ $ingress_ready == true ]] || {
		echo "standalone restart A1 route swap not absorbed: $p" >&2
		exit 1
	}
	sa_restart_query SRCOMMIT "COMMIT; SELECT CONCAT('SRCOMMIT|', CONNECTION_ID(), '|', @@port);" >/dev/null || exit 1
	for attempt in {1..60}; do
		row=$(sa_restart_query "SRTRY$attempt" "SELECT CONCAT('SRTRY$attempt|', CONNECTION_ID(), '|', @@port, '|', COALESCE(DATABASE(),'NULL'), '|', COALESCE(@sa_restart,'NULL'));") || exit 1
		if [[ $(cut -d'|' -f3 <<<"$row") == "$TIDB_PORT_1" ]]; then
			migrated=true
			break
		fi
		sleep 0.25
	done
	[[ $migrated == true &&
		$(cut -d'|' -f2 <<<"$row") != "$baseline_conn" &&
		$(cut -d'|' -f4 <<<"$row") == sa_cross &&
		$(cut -d'|' -f5 <<<"$row") == post ]] || {
		echo "standalone restart new-client migration failed or lost state: $baseline -> $row" >&2
		exit 1
	}
	curl --noproxy '*' --fail --silent --show-error --max-time 5 \
		"http://127.0.0.1:$ka_health_port/health" \
		-o "$run_dir/standalone-restart-after-health.json"
	jq -e '.route_ledger.active >= 1 and
		.route_ledger.incoming == 0 and .route_ledger.outgoing == 0 and
		.route_ledger.unsettled_redirects == 0 and .route_ledger.unsettled_closes == 0' \
		"$run_dir/standalone-restart-after-health.json" >/dev/null || {
		echo "standalone restart migration left route tokens unsettled" >&2
		exit 1
	}
	kill -0 "$KA_SESSION_PID" 2>/dev/null || { echo "standalone restart new client exited" >&2; exit 1; }
	exec 10>&-
	wait "$KA_SESSION_PID" 2>/dev/null || true
	KA_SESSION_PID=
	rm -f "$KA_FIFO"
	KA_FIFO=
	write_state
	printf 'old_pid=%s new_pid=%s old_conn=%s new_baseline_conn=%s migrated_conn=%s\n' \
		"$old_pid" "$new_pid" "$old_conn" "$baseline_conn" "$(cut -d'|' -f2 <<<"$row")" \
		>"$run_dir/standalone-restart-receipt.txt"
	echo "PASS: standalone 0-Go SIGKILL restart recovered SQL/health listeners on new Rust PID $new_pid; old persistent client disconnected; NEW client A0=$TIDB_PORT_0 -> A1=$TIDB_PORT_1 migrated with database and variable intact ($row)"
}
