#!/usr/bin/env python3
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Check the real native process's final persisted and exported byte totals."""
import collections
import gzip
import json
import pathlib
import struct
import sys

root = pathlib.Path(sys.argv[1])
state = root / "tiproxy-work" / "run"
consumer = json.loads((state / "rust-metering-consumer.json").read_text())
outbox = json.loads((state / "metering-outbox.json").read_text())
audit = json.loads((root / "native-control-final.json").read_text())
assert audit["connect_count"] > 0 and audit["forwarded"] > 0
assert not [e for e in audit["route_audit"]["metering_events"] if e["kind"] in ("batch", "ack")], "retired metering frame on live bridge"

wal = (root / "native-producer-final.wal").read_bytes()
assert wal[:8] == b"TPMWAL01"
length, checksum = struct.unpack("<QQ", wal[8:24])
payload = wal[24:]
assert len(payload) == length
hashed = 0xCBF29CE484222325
for byte in payload:
    hashed = ((hashed ^ byte) * 0x100000001B3) & ((1 << 64) - 1)
assert hashed == checksum
pos = 0


def varint():
    global pos
    value = shift = 0
    while True:
        byte = payload[pos]
        pos += 1
        value |= (byte & 127) << shift
        if byte < 128:
            return value
        shift += 7
        assert shift < 70


fields = {}
while pos < len(payload):
    key = varint()
    field, wire = key >> 3, key & 7
    if wire == 0:
        value = varint()
    else:
        assert wire == 2
        size = varint()
        value = payload[pos:pos + size]
        pos += size
    assert field not in fields, "unexpected repeated field/unacked batch"
    fields[field] = value
assert 5 not in fields, "producer retains an unacknowledged batch"
assert fields[1] == 1 and fields[2].decode() == consumer["producer_id"]
assert fields[4] - 1 == consumer["last_applied"] > 0
assert outbox["producer_id"] == consumer["producer_id"]
assert outbox["last_batch_sequence"] == consumer["last_applied"]
assert not consumer["pending"] and not consumer["sources"], "final sources were not consumed"
assert not outbox["data"] and not outbox.get("pending"), "final window was not exported"
expected = collections.defaultdict(lambda: [0, 0, 0])
for row in consumer["totals"]:
    value = expected[row["keyspace"]]
    value[0 if row["public_endpoint"] else 1] += row["response_bytes"]
    value[2] += row["cross_location_bytes"]
actual = collections.defaultdict(lambda: [0, 0, 0])
objects = sorted((root / "meter-objects").rglob("*.json.gz"))
assert objects and sum(v[0] + v[1] for v in expected.values()) > 0
for path in objects:
    data = json.loads(gzip.decompress(path.read_bytes()))
    assert data["self_id"] == outbox["self_id"] and data["shared_pool_id"] == "native-process-probe"
    for row in data["data"]:
        value = actual[row["cluster_id"]]
        for index, key in enumerate(("public_outBound_bytes", "private_outBound_bytes", "crossZone_bytes")):
            value[index] += row[key]["value"]
assert actual == expected, (actual, expected)
receipt = {"result": "PASS", "last_sequence": consumer["last_applied"], "bridge_metering_frames": 0,
           "object_count": len(objects), "totals": dict(actual), "final_sources": 0, "wal_unacked": 0}
(root / "native-meter-receipt.json").write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
print(json.dumps(receipt, sort_keys=True))
