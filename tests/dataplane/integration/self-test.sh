#!/usr/bin/env bash
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "$script_dir/../../.." && pwd)
temp_dir=$(mktemp -d "${TMPDIR:-/tmp}/tiproxy-dataplane-self-test.XXXXXX")
cleanup() {
	case "$temp_dir" in
		"${TMPDIR:-/tmp}"/tiproxy-dataplane-self-test.*) rm -rf "$temp_dir" ;;
	esac
}
trap cleanup EXIT

sha256_file() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
	else
		shasum -a 256 "$1" | awk '{print $1}'
	fi
}

bash -n "$script_dir/run.sh" "$script_dir/qualify-route-owner.sh" \
	"$script_dir/warm-tiup-components.sh"
qualification_plan=$("$script_dir/qualify-route-owner.sh" --print-plan)
if [[ $(wc -l <<<"$qualification_plan" | tr -d ' ') != 48 ]]; then
	echo "T4 qualification plan does not contain exactly 48 physical cells" >&2
	exit 1
fi
if [[ $(grep -c $'\tsentinel\ttls-proxy-zstd$' <<<"$qualification_plan") != 3 ]] ||
	! grep -q $'^M1\tsentinel\ttls-proxy-zstd$' <<<"$qualification_plan" ||
	! grep -q $'^M7\tsentinel\ttls-proxy-zstd$' <<<"$qualification_plan" ||
	! grep -q $'^M9\tsentinel\ttls-proxy-zstd$' <<<"$qualification_plan"; then
	echo "T4 qualification sentinels are not exactly M1/M7/M9" >&2
	exit 1
fi

qualification_design="$script_dir/tiproxy-223-design-final.md"
if [[ $(sha256_file "$qualification_design") != eddcc7fb9ece5e82d45ae3b953567197664d4c6633ef3861a5d6a8f677f06f2e ]]; then
	echo "vendored T4 qualification design is missing or changed" >&2
	exit 1
fi
qualification_workflow="$repo_root/.github/workflows/dataplane-integration.yml"
for required_fragment in \
	't4_qualification:' \
	'cancel-in-progress: ${{ !inputs.t4_qualification }}' \
	'if: github.event_name == '\''workflow_dispatch'\'' && inputs.t4_qualification' \
	'timeout-minutes: 360' \
	'- name: Initialize immutable qualification evidence' \
	'artifact_root="$RUNNER_TEMP/t4-qualification-artifacts"' \
	'echo "DATAPLANE_T4_ARTIFACT_ROOT=$artifact_root" >>"$GITHUB_ENV"' \
	'- name: Preinstall frozen TiUP components serially' \
	'bash tests/dataplane/integration/warm-tiup-components.sh' \
	'- name: Install protobuf compiler' \
	'sudo apt-get install --yes protobuf-compiler' \
	'protoc --version' \
	'set -o pipefail' \
	'design_root=$(cd "$GITHUB_WORKSPACE/../.." && pwd)' \
	'cp tests/dataplane/integration/tiproxy-223-design-final.md \' \
	'"$design_root/notes/tiproxy-223-design-final.md"' \
	'make dataplane-t4-qualification 2>&1 | \' \
	'tee "$DATAPLANE_T4_ARTIFACT_ROOT/qualification.log"' \
	'path: ${{ runner.temp }}/t4-qualification-artifacts'; do
	if ! grep -Fq -- "$required_fragment" "$qualification_workflow"; then
		echo "T4 qualification workflow is missing: $required_fragment" >&2
		exit 1
	fi
done
if [[ $(grep -Fc -- '- name: Preinstall frozen TiUP components serially' "$qualification_workflow") != 2 ]] ||
	[[ $(grep -Fc -- 'run: bash tests/dataplane/integration/warm-tiup-components.sh' "$qualification_workflow") != 2 ]]; then
	echo "both integration jobs must prewarm the frozen TiUP components exactly once" >&2
	exit 1
fi
if [[ $(grep -Fc -- 'tiup "playground:v${TIUP_VERSION}" "$TIDB_VERSION"' "$script_dir/run.sh") != 2 ]] ||
	grep -Fq -- 'tiup playground "$TIDB_VERSION"' "$script_dir/run.sh"; then
	echo "both playgrounds must launch the frozen component version explicitly" >&2
	exit 1
fi
if ! grep -Fq -- 'components=(playground pd tikv tidb ctl)' "$script_dir/warm-tiup-components.sh" ||
	! grep -Fq -- 'components/ctl/${TIDB_VERSION}/etcdctl' "$script_dir/run.sh" ||
	! grep -Fq -- 'record_t4_phase namespace-bootstrap-start' "$script_dir/run.sh" ||
	! grep -Fq -- 'record_t4_phase namespace-bootstrap-complete' "$script_dir/run.sh" ||
	grep -Fq -- 'find "${TIUP_HOME:-${HOME}/.tiup}/components/ctl"' "$script_dir/run.sh"; then
	echo "Rust integration must prewarm and resolve the exact frozen ctl component" >&2
	exit 1
fi

if ! grep -Fq -- 'make -C "$repo_root" rust-build cmd_tiproxy' "$script_dir/qualify-route-owner.sh"; then
	echo "T4 qualification does not build both clean-runner binaries" >&2
	exit 1
fi
for required_fragment in \
	'for binary in "$rust_binary" "$go_binary"; do' \
	'if [[ ! -x $binary ]]; then' \
	'qualification binary missing or not executable: $binary'; do
	if ! grep -Fq -- "$required_fragment" "$script_dir/qualify-route-owner.sh"; then
		echo "T4 qualification is missing its binary-negative guard: $required_fragment" >&2
		exit 1
	fi
done

# The formal recorder is piped through tee so its complete first-failure log
# survives. Keep pipefail explicit in the workflow so a recorder/build failure
# cannot be turned into a successful recording step by tee.
qualification_log="$temp_dir/qualification.log"
if bash -o pipefail -c 'exit 23' 2>&1 | tee "$qualification_log" >/dev/null; then
	echo "T4 qualification log pipeline swallowed the recorder failure" >&2
	exit 1
fi
if [[ -s "$qualification_log" ]]; then
	echo "silent negative qualification probe unexpectedly wrote output" >&2
	exit 1
fi

# Framework-only checks must not require a real TiUP installation or database
# client. These two fakes satisfy preflight discovery but cannot provision or
# query anything; the tested Rust path must stop before either would be used.
mkdir -p "$temp_dir/tools"
cat >"$temp_dir/tools/tiup" <<'FAKE_TIUP'
#!/usr/bin/env bash
case ${1:-} in
	--version)
		echo '1.17.0 tiup'
		;;
	install)
		if [[ -z ${FAKE_TIUP_COMMAND_LOG:-} || $# != 2 ]]; then
			echo 'self-test TiUP install received an unexpected invocation' >&2
			exit 99
		fi
		printf 'install %s\n' "$2" >>"$FAKE_TIUP_COMMAND_LOG"
		;;
	list)
		if [[ -z ${FAKE_TIUP_COMMAND_LOG:-} || $# != 3 || ${3:-} != --installed ]]; then
			echo 'self-test TiUP list received an unexpected invocation' >&2
			exit 99
		fi
		case $2 in
			playground) version=v1.17.0 ;;
			pd | tikv | tidb | ctl) version=v8.5.1 ;;
			*) exit 99 ;;
		esac
		printf 'list %s --installed\n' "$2" >>"$FAKE_TIUP_COMMAND_LOG"
		printf 'Version  Installed\n'
		if [[ ${FAKE_TIUP_MISSING_COMPONENT:-} == "$2" ]]; then
			printf '%s  NO\n' "$version"
		else
			printf '%s  YES\n' "$version"
		fi
		;;
	*)
		echo 'self-test TiUP received an unexpected invocation' >&2
		exit 99
		;;
esac
FAKE_TIUP
cat >"$temp_dir/tools/mysql" <<'FAKE_MYSQL'
#!/usr/bin/env bash
case "${1:-}" in
	--help) echo '  --compression-algorithms=name' ;;
	--version) echo 'mysql self-test client' ;;
	*) echo 'self-test mysql must not execute a query' >&2; exit 99 ;;
esac
FAKE_MYSQL
chmod 0700 "$temp_dir/tools/tiup" "$temp_dir/tools/mysql"

tiup_command_log="$temp_dir/tiup-command.log"
PATH="$temp_dir/tools:$PATH" FAKE_TIUP_COMMAND_LOG="$tiup_command_log" \
	"$script_dir/warm-tiup-components.sh"
cat >"$temp_dir/expected-tiup-command.log" <<'EXPECTED_TIUP_COMMANDS'
install playground:v1.17.0
install pd:v8.5.1
install tikv:v8.5.1
install tidb:v8.5.1
install ctl:v8.5.1
list playground --installed
list pd --installed
list tikv --installed
list tidb --installed
list ctl --installed
EXPECTED_TIUP_COMMANDS
if ! diff -u "$temp_dir/expected-tiup-command.log" "$tiup_command_log"; then
	echo "TiUP prewarm did not install and verify exact components serially" >&2
	exit 1
fi
set +e
PATH="$temp_dir/tools:$PATH" FAKE_TIUP_COMMAND_LOG="$tiup_command_log" \
	FAKE_TIUP_MISSING_COMPONENT=ctl \
	"$script_dir/warm-tiup-components.sh" >"$temp_dir/tiup-missing.out" 2>&1
tiup_missing_status=$?
set -e
if ((tiup_missing_status == 0)); then
	echo "TiUP prewarm accepted a missing frozen component" >&2
	exit 1
fi
grep -Fq 'TiUP component ctl:v8.5.1 is not installed after prewarm' \
	"$temp_dir/tiup-missing.out"

# A required check must report on every pull request while provisioning the
# real topology only for changes that can affect T2 local routing. Exercise
# both sides of that classification with single and mixed path sets.
if [[ $(printf '%s\n' docs/README.md | "$script_dir/t2-required-paths.sh") != false ]]; then
	echo "an unrelated documentation change was classified as T2-relevant" >&2
	exit 1
fi
if [[ $(printf '%s\n' docs/README.md rust/crates/dataplane/src/lib.rs | "$script_dir/t2-required-paths.sh") != true ]]; then
	echo "a Rust dataplane change was not classified as T2-relevant" >&2
	exit 1
fi
for relevant_path in \
	.github/workflows/dataplane-t2-local-route.yml \
	Makefile \
	go.mod \
	lib/config/config.go \
	pkg/controlbridge/bridge.go \
	pkg/server/server.go \
	rust-toolchain.toml \
	rust/Cargo.lock \
	tests/dataplane/integration/run.sh; do
	if [[ $(printf '%s\n' "$relevant_path" | "$script_dir/t2-required-paths.sh") != true ]]; then
		echo "T2-relevant path was not classified: $relevant_path" >&2
		exit 1
	fi
done

# If GitHub cannot provide a trustworthy comparison base, the decision must
# fail open into the real probe rather than falsely satisfying the check.
for missing_base in "" 0000000000000000000000000000000000000000 deadbeefdeadbeefdeadbeefdeadbeefdeadbeef; do
	if [[ $("$script_dir/t2-required-decision.sh" pull_request "$missing_base" HEAD) != true ]]; then
		echo "a missing comparison base did not fail open: '$missing_base'" >&2
		exit 1
	fi
done
if [[ $("$script_dir/t2-required-decision.sh" workflow_dispatch "" HEAD) != true ]]; then
	echo "manual dispatch did not force the real T2 probe" >&2
	exit 1
fi

go test "$repo_root/tests/dataplane/integration/faultproxy"
go test "$repo_root/tests/dataplane/integration/controldropper"
go test "$repo_root/tests/dataplane/integration/controlrejector"

"$script_dir/generate-certs.sh" "$temp_dir/certs" >/dev/null
openssl verify -CAfile "$temp_dir/certs/ca.pem" \
	"$temp_dir/certs/server.pem" "$temp_dir/certs/client.pem" >/dev/null
if [[ -r $temp_dir/certs/server-key.pem && -x $temp_dir/certs/server-key.pem ]]; then
	echo "generated private key is unexpectedly executable" >&2
	exit 1
fi

variants=(plain tls proxy compress-zlib compress-zstd tls-proxy-zstd)
for index in "${!variants[@]}"; do
	output="$temp_dir/render-${variants[$index]}"
	"$script_dir/render-configs.sh" "$output" "${variants[$index]}" "$((10000 + index * 100))" >/dev/null
	if grep -R -n '@[A-Z_][A-Z_]*@' "$output" --include='*.toml' --include='*.env'; then
		echo "unrendered config token in ${variants[$index]}" >&2
		exit 1
	fi
done

cat >"$temp_dir/unredacted.log" <<'REDACTION_INPUT'
safe diagnostic line
password=hunter2
mysql://root:another-secret@127.0.0.1:4000/test
-----BEGIN PRIVATE KEY-----
private material
-----END PRIVATE KEY-----
REDACTION_INPUT
awk -f "$script_dir/redact.awk" "$temp_dir/unredacted.log" >"$temp_dir/redacted.log"
grep -q 'safe diagnostic line' "$temp_dir/redacted.log"
if grep -q -e 'hunter2' -e 'another-secret' -e 'private material' "$temp_dir/redacted.log"; then
	echo "diagnostic redaction leaked test authentication material" >&2
	exit 1
fi

cat >"$temp_dir/tiproxy-rs" <<'FAKE_RUST'
#!/usr/bin/env bash
if [[ ${1:-} == --version ]]; then
	echo 'tiproxy-rs 0.0.0-test'
	exit 0
fi
echo 'only --version is supported' >&2
exit 2
FAKE_RUST
chmod 0700 "$temp_dir/tiproxy-rs"
set +e
PATH="$temp_dir/tools:$PATH" TIPROXY_RS_BIN="$temp_dir/tiproxy-rs" \
	"$script_dir/preflight.sh" --mode rust --variant plain >"$temp_dir/rust-preflight.out" 2>&1
preflight_status=$?
set -e
if ((preflight_status != 78)); then
	echo "incomplete Rust proxy preflight returned $preflight_status, expected 78" >&2
	exit 1
fi
grep -q 'will not substitute a raw TCP relay or the Go dataplane' "$temp_dir/rust-preflight.out"

# Exercise the public entrypoint too. A preflight-only run must preserve exit
# 78 and must not ask TiUP to create or clean a playground tag.
mkdir -p "$temp_dir/tiup/data"
set +e
PATH="$temp_dir/tools:$PATH" TIPROXY_RS_BIN="$temp_dir/tiproxy-rs" TIUP_HOME="$temp_dir/tiup" \
	"$script_dir/run.sh" --mode rust --variant plain \
	--artifact-root "$temp_dir/artifacts" --port-offset 19500 \
	>"$temp_dir/rust-run.out" 2>&1
run_status=$?
set -e
if ((run_status != 78)); then
	echo "incomplete Rust proxy run returned $run_status, expected 78" >&2
	cat "$temp_dir/rust-run.out" >&2
	exit 1
fi
if find "$temp_dir/tiup/data" -mindepth 1 -print -quit | grep -q .; then
	echo "preflight-only run created TiUP data" >&2
	exit 1
fi

# One-sided restart helpers: ownership-checked SIGKILL and the
# three-condition backend-socket removal, exercised with dummy
# processes and sockets (no TiUP, no dataplane).
source "$script_dir/restart-helpers.sh"

# sigkill_owned_process kills a process whose command line matches, and
# refuses one whose command line does not.
sleep 30 &
victim_pid=$!
if ! sigkill_owned_process "$victim_pid" "sleep"; then
	echo "sigkill_owned_process should kill a matching process" >&2
	exit 1
fi
if kill -0 "$victim_pid" 2>/dev/null; then
	echo "sigkill_owned_process left the victim alive" >&2
	exit 1
fi
sleep 30 &
bystander_pid=$!
if sigkill_owned_process "$bystander_pid" "this-does-not-match"; then
	echo "sigkill_owned_process must refuse a command-line mismatch" >&2
	exit 1
fi
if ! kill -0 "$bystander_pid" 2>/dev/null; then
	echo "a refused sigkill must not touch the bystander" >&2
	exit 1
fi
# An empty ownership token must be refused, not treated as "matches
# everything" — the bystander stays alive.
if sigkill_owned_process "$bystander_pid" ""; then
	echo "sigkill_owned_process must refuse an empty ownership token" >&2
	exit 1
fi
if ! kill -0 "$bystander_pid" 2>/dev/null; then
	echo "a refused empty-token sigkill must not touch the bystander" >&2
	exit 1
fi
kill "$bystander_pid" 2>/dev/null || true
wait "$bystander_pid" 2>/dev/null || true

# remove_dead_backend_socket removes a socket whose owner is dead, and
# refuses a live owner, a non-socket, and a still-held socket.
sock="$temp_dir/backend.sock"
python3 - "$sock" <<'PYSOCK'
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(sys.argv[1])
PYSOCK
# The python process has exited, so the socket has no live owner: a made
# up dead PID plus the socket path must be removed.
if ! remove_dead_backend_socket "$sock" 999999; then
	echo "remove_dead_backend_socket should remove a dead-owner socket" >&2
	exit 1
fi
[[ -e $sock ]] && {
	echo "the dead-owner socket was not removed" >&2
	exit 1
}
# Re-create the socket for the negative cases (the success case removed it).
python3 - "$sock" <<'PYSOCK2'
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(sys.argv[1])
PYSOCK2
# An empty / non-numeric owner PID must be refused — it must not be
# treated as "proven dead", so the socket stays.
if remove_dead_backend_socket "$sock" ""; then
	echo "remove_dead_backend_socket must refuse an empty owner PID" >&2
	exit 1
fi
if remove_dead_backend_socket "$sock" "not-a-pid"; then
	echo "remove_dead_backend_socket must refuse a non-numeric owner PID" >&2
	exit 1
fi
[[ -S $sock ]] || {
	echo "a refused invalid-PID removal must leave the socket" >&2
	exit 1
}
# A live owner is refused.
if remove_dead_backend_socket "$sock" "$$"; then
	echo "remove_dead_backend_socket must refuse a live owner PID" >&2
	exit 1
fi
rm -f -- "$sock"
# A non-socket regular file is refused.
regular="$temp_dir/not-a-socket"
: >"$regular"
if remove_dead_backend_socket "$regular" 999999; then
	echo "remove_dead_backend_socket must refuse a non-socket path" >&2
	exit 1
fi
[[ -e $regular ]] || {
	echo "the refused non-socket must not be removed" >&2
	exit 1
}
# A socket still held open by a live process is refused.
held="$temp_dir/held.sock"
python3 - "$held" <<'PYHOLD' &
import socket, sys, time
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(sys.argv[1])
s.listen()
time.sleep(30)
PYHOLD
hold_pid=$!
for _ in {1..50}; do [[ -S $held ]] && break; sleep 0.1; done
if remove_dead_backend_socket "$held" 999999; then
	echo "remove_dead_backend_socket must refuse a still-held socket" >&2
	exit 1
fi
[[ -S $held ]] || {
	echo "the still-held socket must not be removed" >&2
	exit 1
}
kill "$hold_pid" 2>/dev/null || true
wait "$hold_pid" 2>/dev/null || true

# cleanup.sh dropper-front-socket fail-closed: the finalize path must
# never delete a bystander left where the front socket would be (the
# case where a pre-placed regular file made the dropper Lstat-reject and
# exit, leaving a now-gone KA_DROP_PID), yet must still remove a genuine
# leftover socket whose owner is gone.
cleanup_bystander_dir="$temp_dir/cleanup-bystander"
mkdir -p "$cleanup_bystander_dir"
bystander_front="$cleanup_bystander_dir/ka-drop.sock"
: >"$bystander_front" # a REGULAR file, not a socket
cat >"$cleanup_bystander_dir/state.env" <<EOF
KA_DROP_SOCKET=$bystander_front
KA_DROP_PID=99999999
EOF
set +e
"$script_dir/cleanup.sh" "$cleanup_bystander_dir" tiproxy-dp-rust-selftest \
	>"$cleanup_bystander_dir/cleanup.out" 2>&1
bystander_status=$?
set -e
if ((bystander_status == 0)); then
	echo "cleanup must fail when the dropper front path is a bystander regular file" >&2
	exit 1
fi
[[ -f $bystander_front ]] || {
	echo "cleanup deleted a bystander regular file at the front-socket path" >&2
	exit 1
}

cleanup_leftover_dir="$temp_dir/cleanup-leftover"
mkdir -p "$cleanup_leftover_dir"
# Bind under a short /tmp path: macOS caps sun_path near 104 bytes, far
# shorter than the temp_dir the run lives under.
leftover_front="/tmp/tiproxy-selftest-drop-$$.sock"
rm -f "$leftover_front"
python3 - "$leftover_front" <<'PYSOCK3'
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(sys.argv[1])
PYSOCK3
cat >"$cleanup_leftover_dir/state.env" <<EOF
KA_DROP_SOCKET=$leftover_front
KA_DROP_PID=99999999
EOF
set +e
"$script_dir/cleanup.sh" "$cleanup_leftover_dir" tiproxy-dp-rust-selftest \
	>"$cleanup_leftover_dir/cleanup.out" 2>&1
leftover_status=$?
set -e
if ((leftover_status != 0)); then
	echo "cleanup must succeed removing a genuine leftover front socket" >&2
	cat "$cleanup_leftover_dir/cleanup.out" >&2
	exit 1
fi
[[ -e $leftover_front ]] && {
	echo "cleanup did not remove a genuine leftover front socket" >&2
	exit 1
}

# VAL-01 driver-smoke negotiation self-test: locks the fail-closed assertion
# rows (missing-log / 0-line / 2-line / bit-absent / bit-present) plus the
# driver whitelist (unknown-driver rejected) without a real TiDB, so the smoke
# gate cannot silently regress to false-green. `set -e` fails the harness if any
# row misbehaves.
"$repo_root/tests/compatibility/smoke/run-smoke.sh" --self-test

echo "PASS: integration framework self-tests"
