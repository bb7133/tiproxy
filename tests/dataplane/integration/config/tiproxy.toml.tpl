# Generated for the TiProxy dataplane integration topology. Do not use in production.

workdir = "@WORK_DIR@"
enable-traffic-replay = false

[proxy]
addr = "127.0.0.1:@TIPROXY_PORT@"
# Two consecutive SQL listeners: listener A (@TIPROXY_PORT@) is bound
# to cluster-a and listener B (@TIPROXY_PORT_B@) to cluster-b through
# the TiDB `tiproxy-port` topology labels plus routing-rule = "port".
port-range = [@TIPROXY_PORT@, @TIPROXY_PORT_B@]
pd-addrs = "127.0.0.1:@PD_PORT@"
proxy-protocol = "@PROXY_PROTOCOL@"
max-connections = 100
conn-buffer-size = 32768
graceful-wait-before-shutdown = 0
graceful-close-conn-timeout = 5

# Two REAL PD-backed clusters (DPL-07 #41 cluster dimension). The
# explicit list overrides the legacy proxy.pd-addrs fallback.
[[proxy.backend-clusters]]
name = "cluster-a"
pd-addrs = "127.0.0.1:@PD_PORT@"

[[proxy.backend-clusters]]
name = "cluster-b"
pd-addrs = "127.0.0.1:@PD_PORT_B@"

[balance]
routing-rule = "port"

[api]
addr = "127.0.0.1:@TIPROXY_API_PORT@"

[log]
level = "debug"
encoder = "json"

[log.log-file]
filename = "@TIPROXY_LOG@"
max-size = 50
max-days = 1
max-backups = 1

[security]
require-backend-tls = @REQUIRE_BACKEND_TLS@

[security.sql-tls]
ca = "@CA_CERT@"
cert = "@CLIENT_CERT@"
key = "@CLIENT_KEY@"
skip-ca = @SQL_TLS_SKIP_CA@
min-tls-version = "1.2"

[security.server-tls]
ca = "@CA_CERT@"
cert = "@SERVER_CERT@"
key = "@SERVER_KEY@"
min-tls-version = "1.2"
