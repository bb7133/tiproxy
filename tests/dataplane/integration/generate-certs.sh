#!/usr/bin/env bash
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

if [[ $# -ne 1 ]]; then
	echo "usage: $0 OUTPUT_DIRECTORY" >&2
	exit 2
fi

output_dir=$1
umask 077
mkdir -p "$output_dir"

for command_name in openssl mktemp; do
	if ! command -v "$command_name" >/dev/null 2>&1; then
		echo "required command not found: $command_name" >&2
		exit 1
	fi
done

openssl_config=$(mktemp "${TMPDIR:-/tmp}/tiproxy-cert-config.XXXXXX")
cleanup() {
	rm -f "$openssl_config"
}
trap cleanup EXIT

cat >"$openssl_config" <<'CERT_CONFIG'
[req]
distinguished_name = subject
prompt = no

[subject]
CN = TiProxy dataplane integration server

[server_extensions]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @server_alt_names

[server_alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
IP.2 = ::1

[client_extensions]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth
CERT_CONFIG

openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
	-keyout "$output_dir/ca-key.pem" \
	-out "$output_dir/ca.pem" \
	-days 2 -subj "/CN=TiProxy dataplane integration CA" >/dev/null 2>&1

openssl req -newkey rsa:2048 -sha256 -nodes \
	-keyout "$output_dir/server-key.pem" \
	-out "$output_dir/server.csr" \
	-config "$openssl_config" >/dev/null 2>&1
openssl x509 -req -sha256 \
	-in "$output_dir/server.csr" \
	-CA "$output_dir/ca.pem" -CAkey "$output_dir/ca-key.pem" -CAcreateserial \
	-out "$output_dir/server.pem" -days 2 \
	-extfile "$openssl_config" -extensions server_extensions >/dev/null 2>&1

openssl req -newkey rsa:2048 -sha256 -nodes \
	-keyout "$output_dir/client-key.pem" \
	-out "$output_dir/client.csr" \
	-subj "/CN=TiProxy dataplane integration client" >/dev/null 2>&1
openssl x509 -req -sha256 \
	-in "$output_dir/client.csr" \
	-CA "$output_dir/ca.pem" -CAkey "$output_dir/ca-key.pem" -CAcreateserial \
	-out "$output_dir/client.pem" -days 2 \
	-extfile "$openssl_config" -extensions client_extensions >/dev/null 2>&1

rm -f "$output_dir/server.csr" "$output_dir/client.csr" "$output_dir/ca.srl"
chmod 0644 "$output_dir"/*.pem
chmod 0600 "$output_dir"/*-key.pem
openssl verify -CAfile "$output_dir/ca.pem" "$output_dir/server.pem" "$output_dir/client.pem" >/dev/null

echo "generated short-lived test certificates in $output_dir"
