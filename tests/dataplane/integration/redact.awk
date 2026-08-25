# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0

# This deliberately favors removing an entire suspicious line over preserving
# detail. Integration diagnostics are small, so false-positive redaction is a
# safer trade-off than leaking an authentication value into CI artifacts.
{
	lower = tolower($0)
	if (private_key) {
		if (lower ~ /-----end .*private key-----/) {
			private_key = 0
		}
		next
	}
	if (lower ~ /-----begin .*private key-----/) {
		print "[REDACTED PRIVATE KEY]"
		private_key = 1
		next
	}
	if (lower ~ /(^|[^a-z])(password|passwd|secret|access[_-]?key|session[_-]?token|auth[_-]?token)([^a-z]|$)/) {
		print "[REDACTED AUTHENTICATION MATERIAL]"
		next
	}
	line = $0
	gsub(/[^[:space:]\/]+:[^[:space:]@\/]+@/, "[REDACTED]@", line)
	print line
}
