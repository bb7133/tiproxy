#!/usr/bin/env bash
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "$script_dir/../../.." && pwd)
# shellcheck source=versions.env
source "$script_dir/versions.env"

mode=rust
variant=plain
artifact_root=${DATAPLANE_ARTIFACT_ROOT:-$script_dir/artifacts}
port_offset=${DATAPLANE_PORT_OFFSET:-$((10000 + ($$ % 20) * 100))}

while (($# > 0)); do
	case "$1" in
		--mode)
			mode=${2:?missing value for --mode}
			shift 2
			;;
		--variant)
			variant=${2:?missing value for --variant}
			shift 2
			;;
		--artifact-root)
			artifact_root=${2:?missing value for --artifact-root}
			shift 2
			;;
		--port-offset)
			port_offset=${2:?missing value for --port-offset}
			shift 2
			;;
		*)
			echo "unknown argument: $1" >&2
			exit 2
			;;
	esac
done

case "$mode" in
	go | rust) ;;
	*)
		echo "mode must be go or rust" >&2
		exit 2
		;;
esac

if [[ $variant == all ]]; then
	# The FULL range is validated up front: six variants at stride 200
	# (each run consumes two 100-port windows), so the base must leave
	# room for 18900 + 5*200 = 19900. Failing late on index 5 after
	# five expensive successful runs is exactly what this prevents.
	if [[ ! $port_offset =~ ^[0-9]+$ ]] || ((port_offset < 1000 || port_offset > 18900)); then
		echo "port offset for --variant all must be an integer from 1000 through 18900" >&2
		exit 2
	fi
	variants=(plain tls proxy compress-zlib compress-zstd tls-proxy-zstd)
	for index in "${!variants[@]}"; do
		"$0" --mode "$mode" --variant "${variants[$index]}" \
			--artifact-root "$artifact_root" --port-offset "$((port_offset + index * 200))"
	done
	exit 0
fi

case "$variant" in
	plain | tls | proxy | compress-zlib | compress-zstd | tls-proxy-zstd) ;;
	*)
		echo "unknown variant: $variant" >&2
		exit 2
		;;
esac
# Each run consumes TWO 100-port windows (the second backend cluster
# lives at +100), so the cap matches the renderer's.
if [[ ! $port_offset =~ ^[0-9]+$ ]] || ((port_offset < 1000 || port_offset > 19900)); then
	echo "port offset must be an integer from 1000 through 19900" >&2
	exit 2
fi

mkdir -p "$artifact_root"
artifact_root=$(cd "$artifact_root" && pwd)
tag="tiproxy-dp-$mode-$variant-$$"
run_dir="$artifact_root/$tag"
mkdir -p "$run_dir"

finalize() {
	local status=$?
	local cleanup_status=0
	trap - EXIT
	set +e
	"$script_dir/collect-diagnostics.sh" "$run_dir" "$tag"
	"$script_dir/cleanup.sh" "$run_dir" "$tag"
	cleanup_status=$?
	set -e
	if ((status == 0 && cleanup_status != 0)); then
		status=$cleanup_status
	fi
	echo "integration artifacts: $run_dir"
	exit "$status"
}
trap finalize EXIT

set +e
"$script_dir/preflight.sh" --mode "$mode" --variant "$variant" >"$run_dir/preflight.log" 2>&1
preflight_status=$?
set -e
if ((preflight_status != 0)); then
	cat "$run_dir/preflight.log" >&2
	exit "$preflight_status"
fi

rust_binary=
if [[ $mode == rust ]]; then
	# Preflight already verified the binary and its capability contract.
	rust_binary=${TIPROXY_RS_BIN:-$repo_root/rust/target/debug/tiproxy-rs}
fi

make -C "$repo_root" cmd_tiproxy >"$run_dir/go-build.log" 2>&1
go build -o "$run_dir/faultproxy" "$script_dir/faultproxy"
"$script_dir/render-configs.sh" "$run_dir" "$variant" "$port_offset" >"$run_dir/render.log"
# shellcheck disable=SC1090
source "$run_dir/variant.env"

PORTS="$PD_PORT $((2380 + port_offset)) $((20160 + port_offset)) $((20180 + port_offset)) $TIDB_PORT_0 $TIDB_PORT_1 $((10080 + port_offset)) $((10081 + port_offset)) $TIPROXY_PORT $TIPROXY_PORT_B $TIPROXY_API_PORT $FAULT_PORT $FAULT_ADMIN_PORT"
# Second backend cluster's playground window (PORT_OFFSET_B).
PORTS="$PORTS $PD_PORT_B $((2380 + PORT_OFFSET_B)) $((20160 + PORT_OFFSET_B)) $((20180 + PORT_OFFSET_B)) $TIDB_PORT_B $((10080 + PORT_OFFSET_B))"
tag_b="$tag-b"
RUST_HEALTH_PORT=$((8090 + port_offset))
RUST_SOCKET="${TMPDIR:-/tmp}/$tag.sock"
if [[ $mode == rust ]]; then
	# The Go process cedes the SQL listeners entirely: with the gate
	# enabled it serves only the control plane and API, and the Rust
	# process binds proxy.addr from its wire snapshot. The socket lives
	# under /tmp with the run's unique tag: macOS caps sun_path around
	# 104 bytes, far shorter than the artifact directory path.
	printf '\n[rust-dataplane]\nenabled = true\ncontrol-socket = "%s"\n' \
		"$RUST_SOCKET" >>"$run_dir/tiproxy.toml"
	PORTS="$PORTS $RUST_HEALTH_PORT"
fi
FAULT_PROXY_BIN="$run_dir/faultproxy"
TIUP_PID=
TIUP_B_PID=
FAULT_PID=
RUST_PID=
write_state() {
	{
		printf 'TIUP_PID=%q\n' "$TIUP_PID"
		printf 'TIUP_B_PID=%q\n' "$TIUP_B_PID"
		printf 'TAG_B=%q\n' "$tag_b"
		printf 'FAULT_PID=%q\n' "$FAULT_PID"
		printf 'RUST_PID=%q\n' "$RUST_PID"
		printf 'RUST_SOCKET=%q\n' "$RUST_SOCKET"
		printf 'FAULT_PROXY_BIN=%q\n' "$FAULT_PROXY_BIN"
		printf 'PORTS=%q\n' "$PORTS"
	} >"$run_dir/state.env"
}
write_state

for port in $PORTS; do
	if "$FAULT_PROXY_BIN" --probe "127.0.0.1:$port" >/dev/null 2>&1; then
		echo "required port is already in use: $port" >&2
		exit 1
	fi
done

tiup playground "$TIDB_VERSION" --tag "$tag" --without-monitor \
	--host 127.0.0.1 --port-offset "$port_offset" \
	--pd 1 --kv 1 --db 2 --tiflash 0 --db.config "$run_dir/tidb.toml" \
	--tiproxy 1 --tiproxy.binpath "$repo_root/bin/tiproxy" \
	--tiproxy.config "$run_dir/tiproxy.toml" \
	>"$run_dir/tiup-playground.log" 2>&1 &
TIUP_PID=$!
write_state

tiup_data=${TIUP_HOME:-${HOME}/.tiup}/data/$tag
for _ in {1..50}; do
	[[ -d $tiup_data ]] && break
	if ! kill -0 "$TIUP_PID" 2>/dev/null; then
		break
	fi
	sleep 0.1
done
if [[ -d $tiup_data ]]; then
	printf '%s\n' "$run_dir" >"$tiup_data/.tiproxy-integration-owned"
fi

# Second backend cluster: its own playground under its own tag and
# port window, no tiproxy of its own (the main proxy's explicit
# backend-clusters reach both PDs).
tiup playground "$TIDB_VERSION" --tag "$tag_b" --without-monitor \
	--host 127.0.0.1 --port-offset "$PORT_OFFSET_B" \
	--pd 1 --kv 1 --db 1 --tiflash 0 --db.config "$run_dir/tidb-b.toml" \
	--tiproxy 0 \
	>"$run_dir/tiup-playground-b.log" 2>&1 &
TIUP_B_PID=$!
write_state

tiup_data_b=${TIUP_HOME:-${HOME}/.tiup}/data/$tag_b
for _ in {1..50}; do
	[[ -d $tiup_data_b ]] && break
	if ! kill -0 "$TIUP_B_PID" 2>/dev/null; then
		break
	fi
	sleep 0.1
done
if [[ -d $tiup_data_b ]]; then
	printf '%s\n' "$run_dir" >"$tiup_data_b/.tiproxy-integration-owned"
fi

if [[ $mode == rust ]]; then
	control_socket="$RUST_SOCKET"
	# The Go control plane creates the socket when it starts; waiting
	# here keeps the launch independent of client reconnect timing.
	for _ in {1..600}; do
		[[ -S $control_socket ]] && break
		if ! kill -0 "$TIUP_PID" 2>/dev/null; then
			echo "TiUP playground exited before the control socket appeared" >&2
			exit 1
		fi
		sleep 0.1
	done
	if [[ ! -S $control_socket ]]; then
		echo "Rust control socket did not appear: $control_socket" >&2
		exit 1
	fi
	"$rust_binary" --control-socket "$control_socket" --control-uid "$(id -u)" \
		--health-port "$RUST_HEALTH_PORT" \
		>"$run_dir/tiproxy-rs.log" 2>&1 &
	RUST_PID=$!
	write_state
fi

faultproxy_args=(
	--listen "127.0.0.1:$FAULT_PORT"
	--admin "127.0.0.1:$FAULT_ADMIN_PORT"
	--target "127.0.0.1:$TIPROXY_PORT"
)
if [[ $PROXY_ENABLED == true ]]; then
	faultproxy_args+=(--proxy-v2)
fi
"$FAULT_PROXY_BIN" "${faultproxy_args[@]}" >"$run_dir/faultproxy.log" 2>&1 &
FAULT_PID=$!
write_state

if [[ $mode == rust ]]; then
	# Gate the shared readiness phase on the Rust process itself: the
	# health endpoint turns 200 once the first generation applies
	# (independent of TiDB warm-up), and a dead tiproxy-rs fails fast
	# here instead of burning the full readiness timeout.
	rust_ready=false
	for _ in {1..180}; do
		if curl --noproxy '*' --fail --silent --max-time 5 \
			"http://127.0.0.1:$RUST_HEALTH_PORT/health" \
			>"$run_dir/tiproxy-rs-health.json" 2>/dev/null; then
			rust_ready=true
			break
		fi
		if ! kill -0 "$RUST_PID" 2>/dev/null; then
			echo "tiproxy-rs exited before readiness; see tiproxy-rs.log" >&2
			exit 1
		fi
		sleep 1
	done
	if [[ $rust_ready != true ]]; then
		echo "Rust dataplane health endpoint was not ready after 180s" >&2
		exit 1
	fi
fi

# The shared readiness phase is monitored: if the Rust process dies
# mid-phase the run fails immediately instead of burning the timeout.
"$script_dir/readiness.sh" "$run_dir" 180 >"$run_dir/readiness.log" 2>&1 &
READINESS_PID=$!
while kill -0 "$READINESS_PID" 2>/dev/null; do
	if [[ -n ${RUST_PID:-} ]] && ! kill -0 "$RUST_PID" 2>/dev/null; then
		kill "$READINESS_PID" 2>/dev/null
		cat "$run_dir/readiness.log"
		echo "tiproxy-rs died during readiness; see tiproxy-rs.log" >&2
		exit 1
	fi
	sleep 1
done
if ! wait "$READINESS_PID"; then
	cat "$run_dir/readiness.log"
	exit 1
fi
cat "$run_dir/readiness.log"

mysql_tls_args=()
if [[ $TLS_ENABLED == true ]]; then
	mysql_tls_args=(--ssl-mode=VERIFY_IDENTITY --ssl-ca="$CA_CERT" --ssl-cert="$CLIENT_CERT" --ssl-key="$CLIENT_KEY")
else
	mysql_tls_args=(--ssl-mode=DISABLED)
fi
mysql_compression_arg=
case "$COMPRESSION" in
	zlib) mysql_compression_arg=--compression-algorithms=zlib ;;
	zstd) mysql_compression_arg=--compression-algorithms=zstd ;;
esac
mysql_ingress() {
	mysql --batch --skip-column-names --connect-timeout=2 \
		-h 127.0.0.1 -P "$FAULT_PORT" -u root \
		"${mysql_tls_args[@]}" ${mysql_compression_arg:+"$mysql_compression_arg"} -e "$1"
}

select_result=$(mysql_ingress 'SELECT 1')
if [[ $select_result != 1 ]]; then
	echo "unexpected SELECT 1 result: $select_result" >&2
	exit 1
fi

curl --noproxy '*' --fail --silent --show-error -X POST \
	"http://127.0.0.1:$FAULT_ADMIN_PORT/fault/drop-next" -o /dev/null
if mysql_ingress 'SELECT 1' >"$run_dir/drop-next.out" 2>&1; then
	echo "fault injection failed: drop-next SELECT unexpectedly succeeded" >&2
	exit 1
fi
if [[ $(mysql_ingress 'SELECT 1') != 1 ]]; then
	echo "proxy did not recover after the injected connection drop" >&2
	exit 1
fi

# Namespace/topology matrix (DPL-07 #41): three username-resolved
# combinations against the REAL cluster, identical in both modes.
# `proxy.pd-addrs` always registers an implicit PD-backed backend
# cluster, and once ANY backend cluster exists the Go FallbackFetcher
# serves every namespace the full PD topology — `backend.instances`
# is ignored, so no namespace can pin a backend and `SELECT @@port`
# cannot discriminate the rows. The namespaces therefore list BOTH
# real backends (the set routing actually uses), behavior asserts a
# landing inside that set, and the DISCRIMINATING evidence is
# per-connection namespace attribution: each row runs alone against a
# captured log offset, and the freshly appended records must
# attribute that one connection to exactly the expected namespace.
mysql_backend_admin() {
	mysql --batch --skip-column-names --connect-timeout=2 \
		-h 127.0.0.1 -P "$TIDB_PORT_0" -u root --ssl-mode=DISABLED -e "$1"
}
mysql_ingress_as() {
	local user=$1
	local query=$2
	mysql --batch --skip-column-names --connect-timeout=4 \
		-h 127.0.0.1 -P "$FAULT_PORT" -u "$user" \
		"${mysql_tls_args[@]}" ${mysql_compression_arg:+"$mysql_compression_arg"} -e "$query"
}
mysql_backend_admin "CREATE USER IF NOT EXISTS 'alice'@'%'; CREATE USER IF NOT EXISTS 'bob'@'%';"
namespace_api="http://127.0.0.1:$TIPROXY_API_PORT/api/admin/namespace"
curl --noproxy '*' --fail --silent --show-error -X PUT \
	-H 'Content-Type: application/json' \
	-d "{\"namespace\":\"ns-alpha\",\"frontend\":{\"user\":\"alice\"},\"backend\":{\"instances\":[\"127.0.0.1:$TIDB_PORT_0\",\"127.0.0.1:$TIDB_PORT_1\"]}}" \
	"$namespace_api/ns-alpha" -o /dev/null
curl --noproxy '*' --fail --silent --show-error -X PUT \
	-H 'Content-Type: application/json' \
	-d "{\"namespace\":\"ns-beta\",\"frontend\":{\"user\":\"bob\"},\"backend\":{\"instances\":[\"127.0.0.1:$TIDB_PORT_0\",\"127.0.0.1:$TIDB_PORT_1\"]}}" \
	"$namespace_api/ns-beta" -o /dev/null
curl --noproxy '*' --fail --silent --show-error -X POST \
	"$namespace_api/commit?namespace=ns-alpha&namespace=ns-beta" -o /dev/null

# Absorption gate: the committed namespaces become routable once the
# proxy rebuilds its user→namespace map and each router observes the
# PD topology. Every user must then land on a REAL backend.
namespace_resolved() {
	local port
	port=$(mysql_ingress_as "$1" 'SELECT @@port' 2>/dev/null) || return 1
	[[ $port == "$TIDB_PORT_0" || $port == "$TIDB_PORT_1" ]]
}
namespace_ready=false
for _ in {1..30}; do
	if namespace_resolved alice && namespace_resolved bob && namespace_resolved root; then
		namespace_ready=true
		break
	fi
	sleep 1
done
if [[ $namespace_ready != true ]]; then
	{
		echo "namespace absorption failed:"
		for user in alice bob root; do
			echo "  $user -> $(mysql_ingress_as "$user" 'SELECT @@port' 2>&1 | tail -1) (want $TIDB_PORT_0 or $TIDB_PORT_1)"
		done
	} >&2
	exit 1
fi
# Per-connection attribution evidence. In Rust mode the engine's
# closed-schema lifecycle log names the decision-resolved namespace;
# in Go mode the per-namespace router logs every route at debug level
# under its namespace field (the tiup component log lives in the tag
# data directory, still alive here; cleanup removes it later).
if [[ $mode == rust ]]; then
	evidence_files() { printf '%s\n' "$run_dir/tiproxy-rs.log"; }
	evidence_pattern() { printf '"event":"connection_ready".*"namespace":"%s"' "$1"; }
else
	go_log_root="${TIUP_HOME:-${HOME}/.tiup}/data/$tag"
	evidence_files() {
		# EXACTLY the main component log: concatenating multiple
		# matching files would misalign the line-count offsets the
		# delta windows depend on whenever any other file grows
		# (old records would "reappear" inside a fresh tail).
		find "$go_log_root" -type f -name 'tiproxy.log' 2>/dev/null | sort
	}
	evidence_pattern() { printf '"logger":"main\\.nsmgr\\.router\\.policy".*"msg":"route".*"namespace":"%s"' "$1"; }
fi
evidence_lines() {
	local files
	files=$(evidence_files)
	if [[ -z $files ]]; then
		echo 0
		return
	fi
	# shellcheck disable=SC2086
	cat $files 2>/dev/null | wc -l | tr -d ' '
}
evidence_tail() {
	local files
	files=$(evidence_files)
	if [[ -z $files ]]; then
		return
	fi
	# shellcheck disable=SC2086
	cat $files 2>/dev/null | tail -n "+$(($1 + 1))"
}
# One row = one connection run ALONE against a captured log offset:
# the fresh records must attribute it to exactly the expected
# namespace and to NO other, which discriminates all three rows even
# though every namespace routes over the same PD-backed backend set.
attribution_row() {
	local user=$1 expected=$2 offset fresh matched=false
	offset=$(evidence_lines)
	if ! namespace_resolved "$user"; then
		echo "$user query failed during the attribution row" >&2
		return 1
	fi
	for _ in {1..20}; do
		fresh=$(evidence_tail "$offset")
		if grep -qE "$(evidence_pattern "$expected")" <<<"$fresh"; then
			matched=true
			break
		fi
		sleep 0.5
	done
	if [[ $matched != true ]]; then
		echo "missing $mode namespace attribution for $user: $expected" >&2
		return 1
	fi
	local other
	for other in ns-alpha ns-beta default; do
		[[ $other == "$expected" ]] && continue
		if grep -qE "$(evidence_pattern "$other")" <<<"$fresh"; then
			echo "$user connection was also attributed to $other" >&2
			return 1
		fi
	done
}
attribution_row alice ns-alpha || exit 1
attribution_row bob ns-beta || exit 1
attribution_row root default || exit 1
echo "namespace matrix: alice->ns-alpha bob->ns-beta root->default (per-connection route attribution)"

# ---- Cluster x listener matrix (DPL-07 #41 cluster dimension) ----
# Deterministic construction: routing-rule = "port" groups backends by
# their `tiproxy-port` topology label, so listener A can ONLY select
# cluster-a's backends and listener B only cluster-b's — the same
# client (listener) selects the same backend class in both modes,
# exactly. NON-CLAIM: per-cluster NSServer parity is out of scope (the
# wire snapshot does not project NSServers; the Rust cluster dialer
# resolves direct addresses with the system resolver, same as Go with
# no name servers).
mysql_listener_as() {
	local port=$1
	local query=$2
	mysql --batch --skip-column-names --connect-timeout=4 \
		-h 127.0.0.1 -P "$port" -u root \
		"${mysql_tls_args[@]}" ${mysql_compression_arg:+"$mysql_compression_arg"} -e "$query"
}
mysql_backend_on() {
	mysql --batch --skip-column-names --connect-timeout=2 \
		-h 127.0.0.1 -P "$1" -u root --ssl-mode=DISABLED -e "$2"
}
# Absorption gate for the EXACT healthy set: GetTiDBTopology tolerates
# partial merges, so readiness alone can pass with one cluster absent.
# Both listeners must deterministically reach their own cluster before
# any evidence row runs.
# Cluster-B's OWN liveness is checked directly (playground process
# alive + direct SQL against its TiDB), so a proxy-side fallback can
# never mask a dead second cluster.
cluster_matrix_ready=false
for _ in {1..60}; do
	if ! kill -0 "$TIUP_B_PID" 2>/dev/null; then
		echo "cluster-B playground died during absorption; see tiup-playground-b.log" >&2
		tail -20 "$run_dir/tiup-playground-b.log" >&2 || true
		exit 1
	fi
	direct_b=$(mysql_backend_on "$TIDB_PORT_B" 'SELECT 1' 2>/dev/null || true)
	port_a=$(mysql_listener_as "$TIPROXY_PORT" 'SELECT @@port' 2>/dev/null || true)
	port_b=$(mysql_listener_as "$TIPROXY_PORT_B" 'SELECT @@port' 2>/dev/null || true)
	if [[ $direct_b == 1 && ($port_a == "$TIDB_PORT_0" || $port_a == "$TIDB_PORT_1") && $port_b == "$TIDB_PORT_B" ]]; then
		cluster_matrix_ready=true
		break
	fi
	sleep 1
done
if [[ $cluster_matrix_ready != true ]]; then
	{
		echo "cluster/listener absorption failed:"
		echo "  listener $TIPROXY_PORT -> ${port_a:-<none>} (want $TIDB_PORT_0 or $TIDB_PORT_1)"
		echo "  listener $TIPROXY_PORT_B -> ${port_b:-<none>} (want $TIDB_PORT_B)"
	} >&2
	exit 1
fi
# Per-listener, delta-scoped, bidirectionally cross-checked evidence.
# Go: the fresh route record's `target` address must sit in the
# listener's own cluster port set. Rust: the fresh connection_ready
# record must pair the backend address with the cluster NAME. Both
# classes are covered explicitly (one connection per listener), and a
# fresh record pairing the OTHER cluster's port is a hard failure —
# as is any phantom/empty cluster attribution in rust mode.
# The Go route record is asserted in BOTH modes (the Go control plane
# routes in rust mode too): its ONE record must carry the claimed
# group key values=["cluster:listener"], the exact per-group backend
# COUNT, every expected member address, and a target inside the set —
# the per-group exact-membership proof CodexM5 asked readiness for.
go_route_files() {
	# EXACTLY the main component log (see evidence_files): a second
	# matching file growing would shift the concatenated line count
	# and leak old records into fresh windows intermittently.
	find "${TIUP_HOME:-${HOME}/.tiup}/data/$tag" -type f -name 'tiproxy.log' 2>/dev/null | sort
}
go_route_lines() {
	local files
	files=$(go_route_files)
	if [[ -z $files ]]; then
		echo 0
		return
	fi
	# shellcheck disable=SC2086
	cat $files 2>/dev/null | wc -l | tr -d ' '
}
go_route_tail() {
	local files
	files=$(go_route_files)
	[[ -n $files ]] || return 0
	# shellcheck disable=SC2086
	cat $files 2>/dev/null | tail -n "+$(($1 + 1))"
}
# Evidence logs are file-buffered: a record written logically before a
# row can flush physically after its window opens. Each row therefore
# waits for BOTH logs to go quiet before capturing its offsets, so
# earlier phases' late flushes can never pollute the window.
quiesce_evidence_logs() {
	local prev_go=-1 prev_ev=-1 now_go now_ev
	for _ in {1..30}; do
		now_go=$(go_route_lines)
		now_ev=$(evidence_lines)
		if [[ $now_go == "$prev_go" && $now_ev == "$prev_ev" ]]; then
			return 0
		fi
		prev_go=$now_go
		prev_ev=$now_ev
		sleep 0.5
	done
	return 0
}
cluster_row() {
	local listener=$1 cluster=$2 want_ports=$3 other_ports=$4
	local offset go_offset fresh go_fresh port record go_record matched=false
	local expected_num
	expected_num=$(wc -w <<<"$want_ports" | tr -d ' ')
	# The QUERY sits inside the retry loop: a group whose second
	# member has not been absorbed yet routes with a partial
	# backend_num, and that record can never satisfy the full-
	# membership pattern — only a NEW query after absorption can.
	local go_pattern rust_pattern attempt
	for attempt in {1..30}; do
		quiesce_evidence_logs
		offset=$(evidence_lines)
		go_offset=$(go_route_lines)
		port=$(mysql_listener_as "$listener" 'SELECT @@port' 2>/dev/null || true)
		if [[ " $want_ports " != *" $port "* ]]; then
			echo "listener $listener landed on '$port' (want one of: $want_ports)" >&2
			return 1
		fi
		go_pattern="\"msg\":\"route\".*\"values\":\[\"$cluster:$listener\"\].*\"backend_num\":$expected_num.*\"target\":\"127\.0\.0\.1:$port\""
		rust_pattern="\"event\":\"connection_ready\".*\"listener\":\"127\.0\.0\.1:$listener\".*\"backend_addr\":\"127\.0\.0\.1:$port\".*\"cluster\":\"$cluster\""
		for _ in {1..10}; do
			go_fresh=$(go_route_tail "$go_offset")
			go_record=$(grep -E "$go_pattern" <<<"$go_fresh" | head -1 || true)
			if [[ $mode == rust ]]; then
				fresh=$(evidence_tail "$offset")
				record=$(grep -E "$rust_pattern" <<<"$fresh" | head -1 || true)
				if [[ -n $record && -n $go_record ]]; then
					matched=true
					break
				fi
			else
				fresh=$go_fresh
				record=$go_record
				if [[ -n $record ]]; then
					matched=true
					break
				fi
			fi
			sleep 0.5
		done
		[[ $matched == true ]] && break
		sleep 1
	done
	if [[ $matched != true ]]; then
		echo "missing $mode cluster attribution for listener $listener (cluster $cluster, port $port)" >&2
		echo "fresh go route candidates:" >&2
		grep -s '"msg":"route"' <<<"${go_fresh:-}" | tail -3 >&2 || true
		return 1
	fi
	# Exact group membership: the ONE Go route record must list every
	# expected member address (count already pinned by backend_num).
	local member
	for member in $want_ports; do
		if [[ $go_record != *"127.0.0.1:$member"* ]]; then
			echo "group $cluster:$listener route record misses member 127.0.0.1:$member: $go_record" >&2
			return 1
		fi
	done
	# The matched records ARE the review evidence: print them verbatim
	# (addresses and ports only — nothing sensitive).
	printf 'cluster evidence (go route, listener %s): %s\n' "$listener" "$go_record"
	if [[ $mode == rust ]]; then
		printf 'cluster evidence (rust, listener %s): %s\n' "$listener" "$record"
	fi
	# Bidirectional cross-check over BOTH evidence windows, scoped to
	# the per-connection record kinds (route decisions / lifecycle
	# events): the other cluster's ports may not appear in any of this
	# row's fresh ROUTING records — a route record that even SCORED a
	# foreign backend for this listener's group trips it. Background
	# health/observer records legitimately name every backend at debug
	# level and prove nothing about routing, so they are out of scope.
	local other
	for other in $other_ports; do
		if grep '"msg":"route"' <<<"$go_fresh" | grep -q "127\.0\.0\.1:$other"; then
			{
				echo "listener $listener's window has a route record with the other cluster's port $other"
				echo "foreign route records in the window:"
				grep '"msg":"route"' <<<"$go_fresh" | grep "127\.0\.0\.1:$other" | tail -3
			} >&2
			return 1
		fi
		# connection_ready ONLY: a CLOSED record for an earlier
		# phase's connection is written asynchronously after its
		# client disconnects and can land inside this row's window —
		# it is not a routing decision of this row.
		if [[ $mode == rust ]] &&
			grep '"event":"connection_ready"' <<<"$fresh" | grep -q "127\.0\.0\.1:$other"; then
			echo "listener $listener's window has a ready record with the other cluster's port $other" >&2
			return 1
		fi
	done
	if [[ $mode == rust ]]; then
		if grep -qE "\"event\":\"connection_ready\".*\"cluster\":\"(default)?\"" <<<"$fresh"; then
			echo "phantom/empty cluster attribution in listener $listener's window" >&2
			return 1
		fi
	fi
}
cluster_row "$TIPROXY_PORT" cluster-a "$TIDB_PORT_0 $TIDB_PORT_1" "$TIDB_PORT_B" || exit 1
cluster_row "$TIPROXY_PORT_B" cluster-b "$TIDB_PORT_B" "$TIDB_PORT_0 $TIDB_PORT_1" || exit 1
echo "cluster matrix: listener $TIPROXY_PORT->cluster-a listener $TIPROXY_PORT_B->cluster-b (deterministic port routing)"

# ---- No-keyspace-migration (DPL-07 #41 acceptance) ----
# An isolated MatchAll proxy instance puts cluster-a (ks-old) and
# cluster-b (ks-new) into ONE routing group, pins a persistent session
# onto cluster-a via fail-backend-list, then hot-swaps the list so the
# router genuinely tries to push that session to ks-new. The product
# guard must refuse at the shared issuance boundary while a NEW
# connection proves the change absorbed. Keyspaces are injected via
# topology labels (the classic-topology discrimination channel); real
# /keyspaces/tidb/<ks> propagation is locked by PDFetcher unit tests.
ka_sql_port=$((8097 + port_offset))
ka_api_port=$((8098 + port_offset))
ka_health_port=$((8099 + port_offset))
KA_SOCKET="${TMPDIR:-/tmp}/$tag-ka.sock"
for port in "$ka_sql_port" "$ka_api_port" "$ka_health_port"; do
	if "$FAULT_PROXY_BIN" --probe "127.0.0.1:$port" >/dev/null 2>&1; then
		echo "keyspace-guard phase port is already in use: $port" >&2
		exit 1
	fi
done
sed '/^\[rust-dataplane\]/,$d' "$run_dir/tiproxy.toml" >"$run_dir/tiproxy-ka.toml"
python3 - "$run_dir/tiproxy-ka.toml" "$ka_sql_port" "$ka_api_port" "$run_dir" "$TIDB_PORT_1" "$TIDB_PORT_B" <<'PYKA'
import re, sys
path, sql_port, api_port, run_dir, tidb_a1, tidb_b = sys.argv[1:7]
text = open(path).read()
text = re.sub(r'(?m)^workdir = .*$', f'workdir = "{run_dir}/ka-workdir"', text)
text = re.sub(r'(?m)^addr = "127\.0\.0\.1:\d+"$',
              lambda m, it=iter([sql_port, api_port]): f'addr = "127.0.0.1:{next(it)}"',
              text, count=2)
text = re.sub(r'(?m)^filename = .*$', f'filename = "{run_dir}/tiproxy-ka.log"', text)
# MatchAll: no port-range listeners, no port routing rule - one group
# holds every backend of both clusters.
text = re.sub(r'(?m)^port-range = .*\n', '', text)
text = re.sub(r'(?m)^routing-rule = .*\n', '', text)
# Initial pin: cluster-b and cluster-a's second backend are failed, so
# the persistent session can only land on A0/ks-old. The failover
# timeout is far beyond the phase duration - the guard, not a force
# close, must be what the old session experiences.
text = re.sub(r'(?m)^graceful-wait-before-shutdown = 0$',
              'graceful-wait-before-shutdown = 0\n'
              f'fail-backend-list = ["127.0.0.1:{tidb_b}", "127.0.0.1:{tidb_a1}"]\n'
              'failover-timeout = 300',
              text)
open(path, 'w').write(text)
PYKA
if [[ $mode == rust ]]; then
	printf '\n[rust-dataplane]\nenabled = true\ncontrol-socket = "%s"\n' \
		"$KA_SOCKET" >>"$run_dir/tiproxy-ka.toml"
	printf 'KA_SOCKET=%q\n' "$KA_SOCKET" >>"$run_dir/state.env"
fi
"$repo_root/bin/tiproxy" --config "$run_dir/tiproxy-ka.toml" \
	>"$run_dir/tiproxy-ka.out" 2>&1 &
KA_PID=$!
printf 'KA_PID=%q\n' "$KA_PID" >>"$run_dir/state.env"
ka_api_up=false
for _ in {1..100}; do
	if ! kill -0 "$KA_PID" 2>/dev/null; then
		break
	fi
	if curl --noproxy '*' --fail --silent \
		"http://127.0.0.1:$ka_api_port/api/admin/namespace/" -o /dev/null; then
		ka_api_up=true
		break
	fi
	sleep 0.2
done
if [[ $ka_api_up != true ]]; then
	echo "keyspace-guard instance API never came up" >&2
	tail -20 "$run_dir/tiproxy-ka.out" >&2 || true
	exit 1
fi
if [[ $mode == rust ]]; then
	"$rust_binary" --control-socket "$KA_SOCKET" --control-uid "$(id -u)" \
		--health-port "$ka_health_port" \
		>"$run_dir/tiproxy-rs-ka.log" 2>&1 &
	KA_RUST_PID=$!
	printf 'KA_RUST_PID=%q\n' "$KA_RUST_PID" >>"$run_dir/state.env"
	ka_ready=false
	for _ in {1..150}; do
		if ! kill -0 "$KA_RUST_PID" 2>/dev/null; then
			break
		fi
		if curl --noproxy '*' --fail --silent --max-time 5 \
			"http://127.0.0.1:$ka_health_port/" -o /dev/null; then
			ka_ready=true
			break
		fi
		sleep 0.2
	done
	if [[ $ka_ready != true ]]; then
		echo "keyspace-guard rust dataplane never became ready" >&2
		tail -20 "$run_dir/tiproxy-rs-ka.log" >&2 || true
		exit 1
	fi
fi
ka_log_lines() {
	[[ -f "$run_dir/tiproxy-ka.log" ]] || { echo 0; return; }
	wc -l <"$run_dir/tiproxy-ka.log" | tr -d ' '
}
ka_log_tail() {
	[[ -f "$run_dir/tiproxy-ka.log" ]] || return 0
	tail -n "+$(($1 + 1))" "$run_dir/tiproxy-ka.log"
}
# Redirection-capability gate: EVERY backend of BOTH clusters must
# report its signing cert (per-backend structured evidence), and the
# router's AND-aggregate must have flipped to true and never back -
# otherwise rebalance never runs and the "pressure" would be fake.
# The health check logs backends by their STATUS address.
ka_status_addrs=("127.0.0.1:$((10080 + port_offset))" "127.0.0.1:$((10081 + port_offset))" "127.0.0.1:$((10080 + PORT_OFFSET_B))")
ka_caps_ready=false
for _ in {1..60}; do
	caps=0
	for addr in "${ka_status_addrs[@]}"; do
		if grep -qs "\"backend has updated signing cert\".*\"$addr\".*\"support_redirection\":true" "$run_dir/tiproxy-ka.log"; then
			caps=$((caps + 1))
		fi
	done
	if ((caps == 3)) &&
		grep -qs '"updated supporting redirection".*"support":true' "$run_dir/tiproxy-ka.log"; then
		ka_caps_ready=true
		break
	fi
	sleep 1
done
if [[ $ka_caps_ready != true ]]; then
	echo "keyspace-guard phase: not all backends report redirection capability" >&2
	grep -s "signing cert\|supporting redirection" "$run_dir/tiproxy-ka.log" | tail -6 >&2 || true
	exit 1
fi
if grep -qs '"updated supporting redirection".*"support":false' "$run_dir/tiproxy-ka.log"; then
	echo "keyspace-guard phase: router redirection support flipped off" >&2
	exit 1
fi
for addr in "${ka_status_addrs[@]}"; do
	grep -s "\"backend has updated signing cert\".*\"$addr\".*\"support_redirection\":true" "$run_dir/tiproxy-ka.log" |
		head -1 | sed 's/^/redirection capability: /'
done
mysql_ka_root() {
	mysql --batch --skip-column-names --connect-timeout=4 \
		-h 127.0.0.1 -P "$ka_sql_port" -u root \
		"${mysql_tls_args[@]}" ${mysql_compression_arg:+"$mysql_compression_arg"} -e "$1"
}
# EXACT absorption of the initial pin, evidence-first: the structured
# failover records must show B and A1 entering failover and A0 NOT -
# only then is a probe landing on A0 discriminating rather than a
# lucky sequence over three routeable backends. (The startup
# fail-list reaching a new MatchAll group at all is the product fix
# locked by TestStartupFailoverListAppliesToNewMatchAllGroup.)
ka_failover_ready=false
for _ in {1..30}; do
	if grep -qs "\"backend enters failover\".*\"127\.0\.0\.1:$TIDB_PORT_B\"" "$run_dir/tiproxy-ka.log" &&
		grep -qs "\"backend enters failover\".*\"127\.0\.0\.1:$TIDB_PORT_1\"" "$run_dir/tiproxy-ka.log"; then
		ka_failover_ready=true
		break
	fi
	sleep 1
done
if [[ $ka_failover_ready != true ]]; then
	echo "keyspace-guard phase: initial fail-list never produced failover evidence for B and A1" >&2
	grep -s "backend enters failover" "$run_dir/tiproxy-ka.log" | tail -4 >&2 || true
	exit 1
fi
if grep -qs "\"backend enters failover\".*\"127\.0\.0\.1:$TIDB_PORT_0\"" "$run_dir/tiproxy-ka.log"; then
	echo "keyspace-guard phase: A0 unexpectedly entered failover under the initial pin" >&2
	exit 1
fi
grep -s "backend enters failover" "$run_dir/tiproxy-ka.log" | tail -2 | sed 's/^/initial pin evidence: /'
ka_pin_ready=false
for _ in {1..30}; do
	pin_port=$(mysql_ka_root 'SELECT @@port' 2>/dev/null || true)
	if [[ $pin_port == "$TIDB_PORT_0" ]]; then
		ka_pin_ready=true
		break
	fi
	sleep 1
done
if [[ $ka_pin_ready != true ]]; then
	echo "keyspace-guard phase: initial pin never absorbed (landed '$pin_port', want $TIDB_PORT_0)" >&2
	exit 1
fi
# The persistent OLD session: a FIFO-driven mysql client that stays
# open across the dynamic swap. FD 9 keeps the FIFO writable.
KA_FIFO="$run_dir/ka-session.fifo"
mkfifo "$KA_FIFO"
# The guard's sample_conn_id is the PROXY-side connection id, not the
# backend CONNECTION_ID(): capture it from the session's own fresh
# "new connection" record (rust mode: the connection_ready record).
ka_session_offset=$(ka_log_lines)
if [[ $mode == rust ]]; then
	ka_rust_session_offset=$(wc -l <"$run_dir/tiproxy-rs-ka.log" | tr -d ' ')
fi
printf 'KA_FIFO=%q\n' "$KA_FIFO" >>"$run_dir/state.env"
# --unbuffered: the client's stdout goes to a file and would otherwise
# sit in a block buffer - the marker poll needs per-query flushes.
mysql --batch --skip-column-names --force --unbuffered \
	-h 127.0.0.1 -P "$ka_sql_port" -u root \
	"${mysql_tls_args[@]}" ${mysql_compression_arg:+"$mysql_compression_arg"} \
	<"$KA_FIFO" >"$run_dir/ka-session.out" 2>&1 &
KA_SESSION_PID=$!
printf 'KA_SESSION_PID=%q\n' "$KA_SESSION_PID" >>"$run_dir/state.env"
exec 9>"$KA_FIFO"
session_query() {
	local marker=$1 sql=$2 line=
	printf '%s\n' "$sql" >&9
	for _ in {1..40}; do
		line=$(grep -s "^$marker|" "$run_dir/ka-session.out" | tail -1 || true)
		if [[ -n $line ]]; then
			printf '%s\n' "$line"
			return 0
		fi
		if ! kill -0 "$KA_SESSION_PID" 2>/dev/null; then
			echo "persistent session died; tail:" >&2
			tail -5 "$run_dir/ka-session.out" >&2 || true
			return 1
		fi
		sleep 0.5
	done
	echo "persistent session never answered marker $marker" >&2
	return 1
}
baseline=$(session_query BASE "SELECT CONCAT('BASE|', CONNECTION_ID(), '|', @@port);") || exit 1
base_conn_id=$(cut -d'|' -f2 <<<"$baseline")
base_port=$(cut -d'|' -f3 <<<"$baseline")
if [[ $base_port != "$TIDB_PORT_0" ]]; then
	echo "old session landed on '$base_port' (want $TIDB_PORT_0)" >&2
	exit 1
fi
proxy_conn_id=
for _ in {1..20}; do
	if [[ $mode == rust ]]; then
		proxy_conn_id=$(tail -n "+$((ka_rust_session_offset + 1))" "$run_dir/tiproxy-rs-ka.log" |
			grep '"event":"connection_ready"' | head -1 |
			sed -n 's/.*"connection_id":\([0-9]*\).*/\1/p')
	else
		proxy_conn_id=$(ka_log_tail "$ka_session_offset" |
			grep '"new connection"' | head -1 |
			sed -n 's/.*"connID":\([0-9]*\).*/\1/p')
	fi
	[[ -n $proxy_conn_id ]] && break
	sleep 0.5
done
if [[ -z $proxy_conn_id ]]; then
	echo "could not capture the old session's proxy-side connection id" >&2
	exit 1
fi
echo "old session baseline: CONNECTION_ID=$base_conn_id proxy_conn_id=$proxy_conn_id backend=127.0.0.1:$base_port (ks-old)"
# THE DYNAMIC SWAP: fail A0+A1 so only ks-new remains routeable. The
# router now genuinely tries to push the old session to cluster-b.
ka_guard_offset=$(ka_log_lines)
cat > "$run_dir/ka-swap.toml" <<KATOML
[proxy]
fail-backend-list = ["127.0.0.1:$TIDB_PORT_0", "127.0.0.1:$TIDB_PORT_1"]
KATOML
curl --noproxy '*' --fail --silent --show-error -X PUT \
	--data-binary "@$run_dir/ka-swap.toml" \
	"http://127.0.0.1:$ka_api_port/api/admin/config/" -o /dev/null
# Anti-false-pass: a NEW connection must land on ks-new, proving the
# swap absorbed. Only then does the old session's stability MEAN
# anything.
ka_swap_ready=false
for _ in {1..30}; do
	new_port=$(mysql_ka_root 'SELECT @@port' 2>/dev/null || true)
	if [[ $new_port == "$TIDB_PORT_B" ]]; then
		ka_swap_ready=true
		break
	fi
	sleep 1
done
if [[ $ka_swap_ready != true ]]; then
	echo "keyspace-guard phase: swap never absorbed (new connection landed '$new_port', want $TIDB_PORT_B)" >&2
	exit 1
fi
echo "swap absorbed: new connection -> 127.0.0.1:$new_port (ks-new)"
# The guard hit: fresh structured evidence that the router ATTEMPTED
# to migrate ks-old -> ks-new and refused - tied to the old
# connection via sample_conn_id (it is the only connection there).
ka_guard_hit=
for _ in {1..40}; do
	ka_guard_hit=$(ka_log_tail "$ka_guard_offset" |
		grep -s '"skip cross-keyspace redirect".*"from_keyspace":"ks-old".*"to_keyspace":"ks-new"' |
		head -1 || true)
	if [[ -n $ka_guard_hit ]]; then
		break
	fi
	sleep 0.5
done
if [[ -z $ka_guard_hit ]]; then
	echo "keyspace-guard phase: no fresh guard hit after the swap" >&2
	ka_log_tail "$ka_guard_offset" | tail -5 >&2 || true
	exit 1
fi
if [[ $ka_guard_hit != *"\"sample_conn_id\":$proxy_conn_id"* ]]; then
	echo "guard hit is not attributed to the old connection (proxy_conn_id=$proxy_conn_id): $ka_guard_hit" >&2
	exit 1
fi
if [[ $ka_guard_hit != *'"blocked_conn_count":1'* ]]; then
	echo "guard hit does not show exactly the one pinned connection: $ka_guard_hit" >&2
	exit 1
fi
echo "guard hit: $ka_guard_hit"
# No redirect was ever issued for the old connection.
if ka_log_tail "$ka_guard_offset" | grep -qs "\"begin redirect connection\".*\"connID\":$proxy_conn_id"; then
	echo "old connection received a redirect despite the guard" >&2
	exit 1
fi
# Old-session oracles on the SAME session: identity and backend both
# unchanged, still serving.
check=$(session_query CHK "SELECT CONCAT('CHK|', CONNECTION_ID(), '|', @@port);") || exit 1
chk_conn_id=$(cut -d'|' -f2 <<<"$check")
chk_port=$(cut -d'|' -f3 <<<"$check")
if [[ $chk_conn_id != "$base_conn_id" || $chk_port != "$base_port" ]]; then
	echo "old session changed identity/backend: $check (baseline $baseline)" >&2
	exit 1
fi
echo "old session intact after swap: CONNECTION_ID=$chk_conn_id backend=127.0.0.1:$chk_port (ks-old)"
# Restore the initial pin well before failover-timeout, close the old
# session cleanly, and tear the instance down.
cat > "$run_dir/ka-swap.toml" <<KATOML
[proxy]
fail-backend-list = ["127.0.0.1:$TIDB_PORT_B", "127.0.0.1:$TIDB_PORT_1"]
KATOML
curl --noproxy '*' --fail --silent --show-error -X PUT \
	--data-binary "@$run_dir/ka-swap.toml" \
	"http://127.0.0.1:$ka_api_port/api/admin/config/" -o /dev/null
exec 9>&-
for _ in {1..40}; do
	kill -0 "$KA_SESSION_PID" 2>/dev/null || break
	sleep 0.5
done
kill "$KA_SESSION_PID" 2>/dev/null || true
wait "$KA_SESSION_PID" 2>/dev/null || true
if [[ $mode == rust ]]; then
	kill -s INT "$KA_RUST_PID" 2>/dev/null || true
	for _ in {1..100}; do
		kill -0 "$KA_RUST_PID" 2>/dev/null || break
		sleep 0.1
	done
	rm -f "$KA_SOCKET"
fi
kill -s INT "$KA_PID" 2>/dev/null || true
for _ in {1..100}; do
	kill -0 "$KA_PID" 2>/dev/null || break
	sleep 0.1
done
kill "$KA_PID" 2>/dev/null || true
rm -f "$KA_FIFO"
printf 'PORTS=%q\n' "$PORTS $ka_sql_port $ka_api_port $ka_health_port" >>"$run_dir/state.env"
echo "no-keyspace-migration: old session pinned to ks-old under real migration pressure; guard refused ks-new"

# ---- Error parity (DPL-07 #41): the same semantic ERR in both modes.
# The oracle freezes the ERR packet's SEMANTIC fields (code + SQLSTATE
# + message), never handshake bytes. Free-text equality of operator
# diagnostics between modes is NOT asserted — only bind semantics.

# Unknown-namespace row: unreachable under the CURRENT public
# bootstrap/admin semantics, and therefore deliberately absent from
# the real-topology matrix. The refusal ("failed to find a
# namespace", 1105/HY000) requires a runtime with no default
# namespace, which no public path can produce: the namespace store is
# per-process in-memory (pkg/manager/config/manager.go Init builds a
# fresh btree; nothing persists namespaces), server bootstrap
# auto-creates "default" whenever the store is empty
# (pkg/server/server.go), CommitNamespaces only upserts into the live
# map, and the commit API hardcodes its delete flags to false — so
# "default" exists from boot and cannot leave a running process via
# the admin API. Package-internal callers (CommitNamespaces with
# delete flags), injected managers in tests, or a future persistent
# store could still reach the refusal — which is why the vocabulary
# contract stays pinned end-to-end by the session engine e2e
# `rejected_handshake_decision_refuses_the_client`: IF the Go
# handshake handler rejects with ErrNamespaceNotFound, the Rust
# dataplane relays the exact approved message.

# Row 2 (bind conflict): operator parity. Each mode's own listener
# bind must fail fast against an occupied port, name the port in its
# diagnostic, and leave no residue. The holder keeps the fd open for
# the whole phase, proving the conflict is live at bind time.
conflict_port=$((8091 + port_offset))
conflict_admin_port=$((8092 + port_offset))
conflict_api_port=$((8093 + port_offset))
for port in "$conflict_port" "$conflict_admin_port" "$conflict_api_port"; do
	if "$FAULT_PROXY_BIN" --probe "127.0.0.1:$port" >/dev/null 2>&1; then
		echo "conflict-phase port is already in use: $port" >&2
		exit 1
	fi
done
"$FAULT_PROXY_BIN" --listen "127.0.0.1:$conflict_port" \
	--admin "127.0.0.1:$conflict_admin_port" --target 127.0.0.1:1 \
	>"$run_dir/conflict-holder.log" 2>&1 &
HOLDER_PID=$!
printf 'HOLDER_PID=%q\n' "$HOLDER_PID" >>"$run_dir/state.env"

holder_ready=false
for _ in {1..50}; do
	if "$FAULT_PROXY_BIN" --probe "127.0.0.1:$conflict_port" >/dev/null 2>&1; then
		holder_ready=true
		break
	fi
	sleep 0.1
done
if [[ $holder_ready != true ]]; then
	echo "conflict holder never bound" >&2
	exit 1
fi
# The Go instance binds its SQL listener directly (no rust-dataplane
# gate): strip the gate section and repoint every listener/path.
sed '/^\[rust-dataplane\]/,$d' "$run_dir/tiproxy.toml" >"$run_dir/tiproxy-conflict.toml"
python3 - "$run_dir/tiproxy-conflict.toml" "$conflict_port" "$conflict_api_port" "$run_dir" <<'PYCONF'
import re, sys
path, sql_port, api_port, run_dir = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
text = open(path).read()
text = re.sub(r'(?m)^workdir = .*$', f'workdir = "{run_dir}/conflict-workdir"', text)
text = re.sub(r'(?m)^addr = "127\.0\.0\.1:\d+"$',
              lambda m, it=iter([sql_port, api_port]): f'addr = "127.0.0.1:{next(it)}"',
              text, count=2)
text = re.sub(r'(?m)^port-range = .*$', f'port-range = [{sql_port}, {sql_port}]', text)
text = re.sub(r'(?m)^filename = .*$', f'filename = "{run_dir}/tiproxy-conflict.log"', text)
open(path, 'w').write(text)
PYCONF
"$repo_root/bin/tiproxy" --config "$run_dir/tiproxy-conflict.toml" \
	>"$run_dir/tiproxy-conflict.out" 2>&1 &
CONFLICT_PID=$!
printf 'CONFLICT_PID=%q\n' "$CONFLICT_PID" >>"$run_dir/state.env"

conflict_exited=false
for _ in {1..40}; do
	if ! kill -0 "$CONFLICT_PID" 2>/dev/null; then
		conflict_exited=true
		break
	fi
	sleep 0.5
done
if [[ $conflict_exited != true ]]; then
	kill -9 "$CONFLICT_PID" 2>/dev/null || true
	echo "Go bind-conflict instance did not fail within the deadline" >&2
	exit 1
fi
if wait "$CONFLICT_PID"; then
	echo "Go bind-conflict instance exited zero" >&2
	exit 1
fi
if ! grep -Eqs "address already in use|bind" \
	"$run_dir/tiproxy-conflict.out" "$run_dir/tiproxy-conflict.log"; then
	echo "Go bind-conflict diagnostic lacks bind semantics" >&2
	exit 1
fi
if ! grep -qs "$conflict_port" \
	"$run_dir/tiproxy-conflict.out" "$run_dir/tiproxy-conflict.log"; then
	echo "Go bind-conflict diagnostic does not name the port" >&2
	exit 1
fi
if "$FAULT_PROXY_BIN" --probe "127.0.0.1:$conflict_api_port" >/dev/null 2>&1; then
	echo "Go bind-conflict instance left its API listener behind" >&2
	exit 1
fi
if ! "$FAULT_PROXY_BIN" --probe "127.0.0.1:$conflict_port" >/dev/null 2>&1; then
	echo "conflict holder died during the Go bind-conflict check" >&2
	exit 1
fi
if [[ $mode == rust ]]; then
	# The Rust operator-facing listener is the health endpoint, bound
	# at startup before serving precisely so a bad port fails fast.
	"$rust_binary" --control-socket "$run_dir/absent.sock" \
		--control-uid "$(id -u)" --health-port "$conflict_port" \
		>"$run_dir/tiproxy-rs-conflict.out" 2>&1 &
	RUST_CONFLICT_PID=$!
	printf 'RUST_CONFLICT_PID=%q\n' "$RUST_CONFLICT_PID" >>"$run_dir/state.env"

	rust_conflict_exited=false
	for _ in {1..40}; do
		if ! kill -0 "$RUST_CONFLICT_PID" 2>/dev/null; then
			rust_conflict_exited=true
			break
		fi
		sleep 0.5
	done
	if [[ $rust_conflict_exited != true ]]; then
		kill -9 "$RUST_CONFLICT_PID" 2>/dev/null || true
		echo "Rust bind-conflict instance did not fail within the deadline" >&2
		exit 1
	fi
	if wait "$RUST_CONFLICT_PID"; then
		echo "Rust bind-conflict instance exited zero" >&2
		exit 1
	fi
	if ! grep -Eq "bind health endpoint|[Aa]ddress.*in use" \
		"$run_dir/tiproxy-rs-conflict.out"; then
		echo "Rust bind-conflict diagnostic lacks bind semantics" >&2
		exit 1
	fi
	if ! grep -q "$conflict_port" "$run_dir/tiproxy-rs-conflict.out"; then
		echo "Rust bind-conflict diagnostic does not name the port" >&2
		exit 1
	fi
	if ! "$FAULT_PROXY_BIN" --probe "127.0.0.1:$conflict_port" >/dev/null 2>&1; then
		echo "conflict holder died during the Rust bind-conflict check" >&2
		exit 1
	fi
fi
kill "$HOLDER_PID" 2>/dev/null || true
wait "$HOLDER_PID" 2>/dev/null || true
# The conflict ports join the post-run leak sweep.
printf 'PORTS=%q\n' "$PORTS $conflict_port $conflict_admin_port $conflict_api_port" >>"$run_dir/state.env"
echo "error parity: bind conflict -> fast nonzero exit, port named, no residue"

# Row 3 (no healthy backend): TERMINAL phase — it destroys the SQL
# plane, so nothing SQL-visible may follow. Both TiDB servers are
# killed (expected; the shared readiness gate has already completed
# and cleanup stops TiUP itself, so this never reads as a harness
# failure). The poll then pins the oracle to the eviction-complete
# state: mid-race dial failures surface a different message and keep
# polling; only the frozen vocabulary ends the loop — 1105/HY000
# "No available TiDB instances, please make sure TiDB is available"
# (Go: ErrProxyNoBackend in pkg/proxy/backend/error.go, reached from
# router.ErrNoBackend; Rust: the AcquireError::NoBackend client
# refusal).
# Per-port discipline: EACH TiDB port must have exactly one LISTEN
# owner and the two owners must be distinct processes — an already-dead
# backend or an accidentally shared port is a hard error, never a
# silently "successful" double kill. (Under pipefail a no-match lsof
# would abort the capture silently, so each probe is explicitly
# allowed to fail and reports its owners on error.)
# ALL expected TiDB ports across BOTH clusters: a still-healthy
# cluster-B backend would keep the router serving and the 1105 oracle
# would never converge. Each port must have exactly one LISTEN owner,
# all owners must be distinct processes, and each pid's command line
# must carry ITS OWN playground's unique tag path ("/$tag/" never
# matches "/$tag-b/", so cluster-A's check cannot be satisfied by a
# cluster-B process or vice versa).
tidb_pid_0=$(lsof -ti "tcp:$TIDB_PORT_0" -sTCP:LISTEN 2>/dev/null || true)
tidb_pid_1=$(lsof -ti "tcp:$TIDB_PORT_1" -sTCP:LISTEN 2>/dev/null || true)
tidb_pid_b=$(lsof -ti "tcp:$TIDB_PORT_B" -sTCP:LISTEN 2>/dev/null || true)
for pair in "$TIDB_PORT_0:$tidb_pid_0" "$TIDB_PORT_1:$tidb_pid_1" "$TIDB_PORT_B:$tidb_pid_b"; do
	port=${pair%%:*}
	owner=${pair#*:}
	if [[ ! $owner =~ ^[0-9]+$ ]]; then
		{
			echo "port $port must have exactly one LISTEN owner for the no-backend row; got: '$owner'"
			lsof -i "tcp:$port" || true
		} >&2
		exit 1
	fi
done
if [[ $tidb_pid_0 == "$tidb_pid_1" || $tidb_pid_0 == "$tidb_pid_b" || $tidb_pid_1 == "$tidb_pid_b" ]]; then
	echo "TiDB ports share a LISTEN owner ($tidb_pid_0/$tidb_pid_1/$tidb_pid_b); refusing the no-backend row" >&2
	exit 1
fi
for pair in "$tag:$tidb_pid_0" "$tag:$tidb_pid_1" "$tag_b:$tidb_pid_b"; do
	owner_tag=${pair%%:*}
	pid=${pair#*:}
	pid_cmd=$(ps -p "$pid" -o command= 2>/dev/null || true)
	if [[ $pid_cmd != *"/$owner_tag/"* ]]; then
		echo "refusing to kill PID $pid for the no-backend row: not owned by tag $owner_tag: $pid_cmd" >&2
		exit 1
	fi
done
tidb_pids="$tidb_pid_0
$tidb_pid_1
$tidb_pid_b"
# Source-branch evidence is delta-scoped to the no-backend window:
# only records logged AFTER the kill count (same discipline as the
# matrix rows).
if [[ $mode == go ]]; then
	go_evidence_offset=$(evidence_lines)
fi
echo "no-backend row: killing TiDB listeners: $(tr '\n' ' ' <<<"$tidb_pids")"
# shellcheck disable=SC2086
kill -9 $tidb_pids
no_backend_ok=false
root_err=
for _ in {1..60}; do
	# The client failing IS the expected outcome: the capture must
	# not let pipefail turn it into a silent abort.
	root_err=$(mysql_ingress_as root 'SELECT 1' 2>&1 >/dev/null | tail -1 || true)
	if grep -q "ERROR 1105 (HY000)" <<<"$root_err" &&
		grep -q "No available TiDB instances, please make sure TiDB is available" <<<"$root_err"; then
		no_backend_ok=true
		break
	fi
	sleep 1
done
if [[ $no_backend_ok != true ]]; then
	echo "no-backend parity failed; last client error: $root_err" >&2
	exit 1
fi
if [[ $mode == go ]]; then
	# Source-branch evidence: ONE fresh record must carry BOTH the
	# get-backend failure and, in its structured last_err field, the
	# frozen ErrProxyNoBackend text — a generic "get backend failed"
	# alone could be an earlier dial/EOF retry from the eviction race,
	# which proves nothing about the branch that refused the client.
	# The client's 1105 and this log record are written near-
	# simultaneously: the record can land milliseconds after the
	# client observed the refusal, so the read retries briefly.
	go_source_evidence=false
	for _ in {1..20}; do
		if evidence_tail "$go_evidence_offset" |
			grep -Eqs '"get backend failed".*"last_err":"No available TiDB instances, please make sure TiDB is available"'; then
			go_source_evidence=true
			break
		fi
		sleep 0.5
	done
	if [[ $go_source_evidence != true ]]; then
		{
			echo "Go no-backend source-branch evidence missing from the row's window"
			echo "fresh get-backend records were:"
			evidence_tail "$go_evidence_offset" | grep -s "get backend failed" | tail -5
		} >&2
		exit 1
	fi
fi
echo "error parity: no healthy backend -> 1105/HY000 'No available TiDB instances'"

if [[ $mode == rust ]]; then
	echo "PASS: Rust dataplane $variant executed SELECT 1, namespace matrix, keyspace guard, error parity, and recovered from drop-next"
else
	echo "PASS: Go baseline $variant executed SELECT 1, namespace matrix, keyspace guard, error parity, and recovered from drop-next"
fi
