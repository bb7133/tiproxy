#!/usr/bin/env python3
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Regress the live batch4 -> snapshot -> ACK4 boundary from run 35475697669.

The framework supplies its normal audit fixture. Passing the sealed failing
KA audit instead replays the exact original bytes with the same assertions.
The appended ACK is synthetic test input, not evidence about the old run.
"""

import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest


spec = importlib.util.spec_from_file_location(
    "receipt", Path(__file__).with_name("write-t4-row-receipt.py"))
receipt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(receipt)
source = Path(sys.argv.pop(1)).read_bytes()
seed = json.loads(source)


class CaptureAuditTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.output = Path(self.directory.name) / "final.json"
        self.now = 0.0
        self.calls = 0
        state = copy.deepcopy(seed)
        audit = state["route_audit"]
        # Preserve the sealed raw bytes when supplied; otherwise reproduce its
        # exact event order using the existing framework's normal fixture.
        if audit["metering_batches"] == 4 and audit["metering_acks"] == 3:
            self.pending = source
        else:
            events = audit["metering_events"][:2]
            fingerprint = audit["metering_events"][2]["producer_fingerprint"]
            for sequence in range(1, 5):
                for kind in (["batch", "ack"] if sequence < 4 else ["batch"]):
                    events.append({
                        "ordinal": len(events) + 1, "kind": kind,
                        "direction": "rust_to_go" if kind == "batch" else "go_to_rust",
                        "sequence": sequence, "producer_fingerprint": fingerprint,
                    })
            audit.update(metering_events=events, metering_batches=4, metering_acks=3)
            self.pending = json.dumps(state).encode()
        state = json.loads(self.pending)
        audit = state["route_audit"]
        ack = dict(audit["metering_events"][-1], ordinal=10, kind="ack", direction="go_to_rust")
        audit["metering_events"].append(ack)
        audit.update(metering_acks=4, max_metering_ack_sequence=4)
        state["forwarded"] += 1
        self.settled = json.dumps(state).encode()

    def sleep(self, duration):
        self.now += duration

    def capture(self, snapshots):
        def fetch(remaining):
            self.assertGreater(remaining, 0)
            value = snapshots[min(self.calls, len(snapshots) - 1)]
            self.calls += 1
            return value
        receipt.capture_route_audit(
            "unused", self.output, timeout=0.25, fetch=fetch,
            clock=lambda: self.now, sleep=self.sleep)

    def test_delayed_ack_keeps_first_snapshot_and_strict_oracle(self):
        self.output.write_bytes(self.pending)
        with self.assertRaises(receipt.PendingMeteringAck):
            receipt.validate_route_audit(self.output)
        self.output.unlink()
        self.capture([self.pending, self.settled])
        self.assertEqual(self.calls, 2)
        self.assertEqual(self.output.with_name("final-first.json").read_bytes(), self.pending)
        self.assertEqual(receipt.validate_route_audit(self.output)["metering_acks"], 4)

    def test_permanent_missing_ack_times_out_and_remains_rejected(self):
        with self.assertRaisesRegex(ValueError, "timed out"):
            self.capture([self.pending])
        self.assertEqual(self.now, 0.25)
        self.assertEqual(self.output.read_bytes(), self.pending)
        with self.assertRaises(receipt.PendingMeteringAck):
            receipt.validate_route_audit(self.output)

    def test_protocol_error_is_not_retried_as_pending_ack(self):
        state = json.loads(self.pending)
        state["route_audit"]["protocol_errors"] = 1
        with self.assertRaisesRegex(ValueError, "protocol errors"):
            self.capture([json.dumps(state).encode(), self.settled])
        self.assertEqual(self.calls, 1)

    def test_capture_does_not_accept_reset_audit_history(self):
        state = json.loads(self.settled)
        state["route_audit"]["metering_events"][0]["direction"] = "go_to_rust"
        with self.assertRaisesRegex(ValueError, "history changed"):
            self.capture([self.pending, json.dumps(state).encode()])


if __name__ == "__main__":
    unittest.main()
