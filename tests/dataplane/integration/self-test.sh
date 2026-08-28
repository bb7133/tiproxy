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

# Framework-only checks must not require a real TiUP installation or database
# client. These two fakes satisfy preflight discovery but cannot provision or
# query anything; the tested Rust path must stop before either would be used.
mkdir -p "$temp_dir/tools"
cat >"$temp_dir/tools/tiup" <<'FAKE_TIUP'
#!/usr/bin/env bash
if [[ ${1:-} == --version ]]; then
	echo '1.17.0 tiup'
	exit 0
fi
echo 'self-test TiUP must not be invoked beyond --version' >&2
exit 99
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

go test "$repo_root/tests/dataplane/integration/faultproxy"
go test "$repo_root/tests/dataplane/integration/controldropper"

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

echo "PASS: integration framework self-tests"
