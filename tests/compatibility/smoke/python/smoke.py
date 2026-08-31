# Copyright 2026 PingCAP, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""VAL-01 smoke adapter for the MySQL Connector/Python client.

Runs exactly one workload per invocation against a live TiProxy SQL listener
and exits 0 on success, non-zero on failure. It asserts only the CLIENT side
(the operation succeeds and returns the expected value); the PROXY-side
negotiation assertion (that TLS/compression was actually negotiated, never
silently downgraded) is done by the orchestrator from the dataplane's
connection-close log. It never prints packet payloads.

It requests only the capabilities Connector/Python supports: zlib compression
(compress=True); it does not request zstd.
"""

import argparse
import sys

import mysql.connector


def build_config(args):
    cfg = {
        "host": args.host,
        "port": args.port,
        "user": args.user,
        "password": args.password,
        "database": args.database,
        "connection_timeout": 15,
        "use_pure": True,
    }
    if args.attr:
        # A unique connection attribute the proxy echoes into its close log so
        # the orchestrator correlates this exact connection's negotiated caps.
        cfg["conn_attrs"] = {"tiproxy_smoke_case": args.attr}
    if args.workload == "tls":
        if not args.ca_file:
            raise SystemExit("tls workload requires --ca-file")
        cfg["ssl_ca"] = args.ca_file
        cfg["ssl_verify_cert"] = True
        # ssl_verify_identity checks the server cert SAN/CN against the host;
        # only enable it when the fixture cert is issued for the connect host.
        if args.verify_identity:
            cfg["ssl_verify_identity"] = True
    elif args.workload == "compress-zlib":
        cfg["compress"] = True
    return cfg


def workload_connect(conn):
    cur = conn.cursor()
    cur.execute("SELECT 1")
    row = cur.fetchone()
    cur.close()
    if row is None or row[0] != 1:
        raise RuntimeError(f"SELECT 1 returned {row!r}")


def workload_crud(conn):
    cur = conn.cursor()
    cur.execute(
        "CREATE TEMPORARY TABLE tiproxy_smoke (id INT PRIMARY KEY, v VARCHAR(32))"
    )
    cur.execute("INSERT INTO tiproxy_smoke (id, v) VALUES (1, 'hello')")
    cur.execute("SELECT v FROM tiproxy_smoke WHERE id = 1")
    row = cur.fetchone()
    cur.close()
    if row is None or row[0] != "hello":
        raise RuntimeError(f"CRUD returned {row!r}, want ('hello',)")


def workload_prepared(conn):
    # A server-side prepared statement (COM_STMT_PREPARE/EXECUTE) with bound
    # parameters, exercising the binary protocol through the proxy.
    cur = conn.cursor(prepared=True)
    cur.execute("SELECT ? + ?", (40, 2))
    row = cur.fetchone()
    cur.close()
    if row is None or row[0] != 42:
        raise RuntimeError(f"prepared sum = {row!r}, want (42,)")


WORKLOADS = {
    "connect": workload_connect,
    "crud": workload_crud,
    "tls": workload_connect,
    "compress-zlib": workload_connect,
    "prepared": workload_prepared,
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=6000)
    parser.add_argument("--user", default="root")
    parser.add_argument("--password", default="")
    parser.add_argument("--database", default="test")
    parser.add_argument("--ca-file", dest="ca_file", default="")
    parser.add_argument("--server-name", dest="server_name", default="")
    parser.add_argument("--verify-identity", action="store_true")
    parser.add_argument("--attr", default="")
    parser.add_argument("--workload", required=True, choices=sorted(WORKLOADS))
    args = parser.parse_args()

    try:
        conn = mysql.connector.connect(**build_config(args))
    except Exception as exc:  # noqa: BLE001 - report any connect/auth failure
        print(f"FAIL python {args.workload}: connect/auth: {exc}", file=sys.stderr)
        return 1
    try:
        WORKLOADS[args.workload](conn)
    except Exception as exc:  # noqa: BLE001 - report any workload failure
        print(f"FAIL python {args.workload}: {exc}", file=sys.stderr)
        return 1
    finally:
        conn.close()

    print(f"PASS python {args.workload}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
