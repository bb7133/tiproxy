# Generated for the TiProxy dataplane integration topology. Do not use in production.

workdir = "@WORK_DIR@"
enable-traffic-replay = false

[proxy]
addr = "127.0.0.1:@TIPROXY_PORT@"
pd-addrs = "127.0.0.1:@PD_PORT@"
proxy-protocol = "@PROXY_PROTOCOL@"
max-connections = 100
conn-buffer-size = 32768
graceful-wait-before-shutdown = 0
graceful-close-conn-timeout = 5

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
