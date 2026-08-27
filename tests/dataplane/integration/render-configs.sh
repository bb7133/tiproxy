#!/usr/bin/env bash
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

if [[ $# -ne 3 ]]; then
	echo "usage: $0 OUTPUT_DIRECTORY VARIANT PORT_OFFSET" >&2
	exit 2
fi

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
output_dir=$1
variant=$2
port_offset=$3

case "$variant" in
	plain | tls | proxy | compress-zlib | compress-zstd | tls-proxy-zstd) ;;
	*)
		echo "unknown variant: $variant" >&2
		exit 2
		;;
esac
# The run consumes TWO 100-port windows: the second backend cluster's
# playground lives at PORT_OFFSET+100.
if [[ ! $port_offset =~ ^[0-9]+$ ]] || ((port_offset < 1000 || port_offset > 19900)); then
	echo "PORT_OFFSET must be an integer from 1000 through 19900" >&2
	exit 2
fi
port_offset_b=$((port_offset + 100))

mkdir -p "$output_dir"
output_dir=$(cd "$output_dir" && pwd)
cert_dir="$output_dir/certs"
work_dir="$output_dir/tiproxy-work"
mkdir -p "$work_dir"

tls_enabled=false
proxy_enabled=false
compression=none
case "$variant" in
	tls)
		tls_enabled=true
		;;
	proxy)
		proxy_enabled=true
		;;
	compress-zlib)
		compression=zlib
		;;
	compress-zstd)
		compression=zstd
		;;
	tls-proxy-zstd)
		tls_enabled=true
		proxy_enabled=true
		compression=zstd
		;;
esac

ca_cert=
server_cert=
server_key=
client_cert=
client_key=
require_backend_tls=false
sql_tls_skip_ca=true
if [[ $tls_enabled == true ]]; then
	"$script_dir/generate-certs.sh" "$cert_dir"
	ca_cert="$cert_dir/ca.pem"
	server_cert="$cert_dir/server.pem"
	server_key="$cert_dir/server-key.pem"
	client_cert="$cert_dir/client.pem"
	client_key="$cert_dir/client-key.pem"
	require_backend_tls=true
	sql_tls_skip_ca=false
fi

proxy_protocol=
proxy_networks=
proxy_fallbackable=true
if [[ $proxy_enabled == true ]]; then
	proxy_protocol=v2
	proxy_networks='*'
	# TiProxy still emits and accepts v2 in this variant. Fallback is retained so
	# TiUP and the readiness script can independently inspect both TiDB nodes.
	proxy_fallbackable=true
fi

pd_port=$((2379 + port_offset))
tidb_port_0=$((4000 + port_offset))
tidb_port_1=$((4001 + port_offset))
tiproxy_port=$((6000 + port_offset))
# port-range listeners must be consecutive: listener B is A+1.
tiproxy_port_b=$((6001 + port_offset))
tiproxy_api_port=$((3080 + port_offset))
fault_port=$((6100 + port_offset))
fault_admin_port=$((18474 + port_offset))
# Second backend cluster (its own playground window).
pd_port_b=$((2379 + port_offset_b))
tidb_port_b=$((4000 + port_offset_b))

sed_escape() {
	local value=$1
	value=${value//\\/\\\\}
	value=${value//&/\\&}
	value=${value//|/\\|}
	printf '%s' "$value"
}

render() {
	local input=$1
	local output=$2
	sed \
		-e "s|@CA_CERT@|$(sed_escape "$ca_cert")|g" \
		-e "s|@SERVER_CERT@|$(sed_escape "$server_cert")|g" \
		-e "s|@SERVER_KEY@|$(sed_escape "$server_key")|g" \
		-e "s|@CLIENT_CERT@|$(sed_escape "$client_cert")|g" \
		-e "s|@CLIENT_KEY@|$(sed_escape "$client_key")|g" \
		-e "s|@PROXY_NETWORKS@|$(sed_escape "$proxy_networks")|g" \
		-e "s|@PROXY_FALLBACKABLE@|$proxy_fallbackable|g" \
		-e "s|@PROXY_PROTOCOL@|$proxy_protocol|g" \
		-e "s|@REQUIRE_BACKEND_TLS@|$require_backend_tls|g" \
		-e "s|@SQL_TLS_SKIP_CA@|$sql_tls_skip_ca|g" \
		-e "s|@WORK_DIR@|$(sed_escape "$work_dir")|g" \
		-e "s|@PD_PORT@|$pd_port|g" \
		-e "s|@PD_PORT_B@|$pd_port_b|g" \
		-e "s|@TIPROXY_PORT@|$tiproxy_port|g" \
		-e "s|@TIPROXY_PORT_B@|$tiproxy_port_b|g" \
		-e "s|@TIPROXY_API_PORT@|$tiproxy_api_port|g" \
		-e "s|@TIPROXY_LOG@|$(sed_escape "$output_dir/tiproxy.log")|g" \
		"$input" >"$output"
}

render "$script_dir/config/tidb.toml.tpl" "$output_dir/tidb.toml"
render "$script_dir/config/tiproxy.toml.tpl" "$output_dir/tiproxy.toml"
# Listener->cluster binding (routing-rule = "port"): cluster A's TiDB
# instances carry listener A's port label, cluster B's carry listener
# B's. Each playground has its own --db.config, so the label is
# per-cluster by construction.
printf '\n[labels]\ntiproxy-port = "%s"\n' "$tiproxy_port" >>"$output_dir/tidb.toml"
render "$script_dir/config/tidb.toml.tpl" "$output_dir/tidb-b.toml"
printf '\n[labels]\ntiproxy-port = "%s"\n' "$tiproxy_port_b" >>"$output_dir/tidb-b.toml"

{
	printf 'VARIANT=%q\n' "$variant"
	printf 'PORT_OFFSET=%q\n' "$port_offset"
	printf 'TLS_ENABLED=%q\n' "$tls_enabled"
	printf 'PROXY_ENABLED=%q\n' "$proxy_enabled"
	printf 'COMPRESSION=%q\n' "$compression"
	printf 'PD_PORT=%q\n' "$pd_port"
	printf 'TIDB_PORT_0=%q\n' "$tidb_port_0"
	printf 'TIDB_PORT_1=%q\n' "$tidb_port_1"
	printf 'TIPROXY_PORT=%q\n' "$tiproxy_port"
	printf 'TIPROXY_PORT_B=%q\n' "$tiproxy_port_b"
	printf 'TIPROXY_API_PORT=%q\n' "$tiproxy_api_port"
	printf 'FAULT_PORT=%q\n' "$fault_port"
	printf 'FAULT_ADMIN_PORT=%q\n' "$fault_admin_port"
	printf 'PORT_OFFSET_B=%q\n' "$port_offset_b"
	printf 'PD_PORT_B=%q\n' "$pd_port_b"
	printf 'TIDB_PORT_B=%q\n' "$tidb_port_b"
	printf 'CA_CERT=%q\n' "$ca_cert"
	printf 'SERVER_CERT=%q\n' "$server_cert"
	printf 'SERVER_KEY=%q\n' "$server_key"
	printf 'CLIENT_CERT=%q\n' "$client_cert"
	printf 'CLIENT_KEY=%q\n' "$client_key"
} >"$output_dir/variant.env"

echo "$output_dir/variant.env"
