#!/usr/bin/env python3
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Every applied-metrics mutant must compile and fail its named live/boundary row."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import urllib.request


def main():
    repo = Path(__file__).resolve().parents[3]
    connection = json.loads(Path(os.environ["CP003_CONNECTION_FILE"]).read_text())
    http = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    live = "module::tests::metrics::live::metric_module_real_etcd_cleanup_and_delayed_http"
    topology = "control-topology"
    external = "control-external"
    with tempfile.TemporaryDirectory(prefix="cpmetric-applied-mutations-") as directory:
        root = Path(directory)
        shutil.copytree(repo / "rust", root / "rust", ignore=shutil.ignore_patterns("target", ".tools"))
        environment = dict(os.environ, CARGO_TARGET_DIR=str(root / "target"))

        def compile_candidate(package):
            command = ["cargo", "test", "--no-run", "--locked", "--offline", "--message-format=json", "--manifest-path", str(root / "rust/Cargo.toml"), "-p", package, "--lib"]
            result = subprocess.run(command, env=environment, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=600)
            if result.returncode:
                raise RuntimeError("candidate did not compile:\n" + result.stderr + result.stdout)
            artifacts = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
            binaries = [item["executable"] for item in artifacts if item.get("reason") == "compiler-artifact" and item.get("executable") and item["target"]["name"] == package.replace("-", "_")]
            if len(binaries) != 1:
                raise RuntimeError(f"expected one test binary: {binaries}")
            return binaries[0]

        def observe(binary, test, ignored=False):
            # Reset the real cleanup gate after a deliberately failed live row.
            with http.open(urllib.request.Request(connection["control_url"] + "/release-cleanup", method="POST"), timeout=5):
                pass
            command = [binary, test, "--nocapture"] + (["--ignored"] if ignored else [])
            return subprocess.run(command, env=environment, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=45)

        def baseline():
            for package, test in [(external, "metric_"), (topology, "metric_")]:
                binary = compile_candidate(package)
                result = observe(binary, test)
                if result.returncode or "test result: ok." not in result.stdout:
                    raise RuntimeError("isolated baseline/restoration failed:\n" + result.stdout)
                if package == topology:
                    result = observe(binary, live, True)
                    if result.returncode or "CP-METRIC-APPLIED all live rows passed" not in result.stdout:
                        raise RuntimeError("isolated live baseline/restoration failed:\n" + result.stdout)

        base = root / "rust/crates"
        originals = {path: (base / path).read_text() for path in [
            "control-topology/src/module.rs", "control-topology/src/metric_source.rs",
            "control-topology/src/discovery_publish.rs", "control-external/src/io_fence.rs",
            "control-external/src/cluster_http.rs", "control-etcd/src/authority.rs", "control-external/src/etcd.rs",
        ]}
        feed = originals["control-topology/src/metric_source.rs"]
        start = feed.index("        if slot.terminal()", feed.index("    pub fn with_current"))
        end = feed.index("        Some(publish())", start)
        final_guard = feed[start:end]
        cases = [
            ("late-material-withdrawal", "control-topology/src/module.rs", "self.metrics.withdraw_material();", "// mutation: defer metrics withdrawal", topology, live, "METRIC_REAL_CLEANUP_EARLY_REVOKE", True),
            ("numeric-source-equality", "control-topology/src/metric_source.rs", "Arc::ptr_eq(&source, &generation.source)", "source.client_epoch == generation.source.client_epoch", topology, "metric_noop_retains_capture", "METRIC_SAME_VALUE_R_ABA", False),
            ("capture-ignores-feed-gate", "control-topology/src/metric_source.rs", "self.gate.is_live() && self.generation.is_live()", "self.generation.is_live()", topology, "metric_noop_retains_capture", "METRIC_SAME_VALUE_R_ABA", False),
            ("publication-skips-final-check", "control-topology/src/metric_source.rs", final_guard, "        let _ = &slot;\n", topology, "metric_material_withdrawal_revokes", "METRIC_FINAL_PUBLICATION", False),
            ("writer-drop-keeps-feed", "control-topology/src/metric_source.rs", "impl Drop for MetricPublication {\n    fn drop(&mut self) {\n        self.close();", "impl Drop for MetricPublication {\n    fn drop(&mut self) {\n        // mutation: no terminal close", topology, "metric_unique_writer_drop", "METRIC_TERMINAL_CAPTURE", False),
            ("capture-ignores-mode-gate", "control-topology/src/metric_source.rs", "            && self.mode.is_live()", "            // mutation: no mode fence", topology, "metric_direct_source_mode", "METRIC_DIRECT_mode_FENCE", False),
            ("discovery-ignores-original-owner", "control-topology/src/discovery_publish.rs", "self.owner.is_current()\n            && self.gate.is_live()", "self.gate.is_live()", topology, "metric_discovery_capture_original_owner", "METRIC_DISCOVERY_OWNER_OR_DROP", False),
            ("discovery-numeric-identity", "control-topology/src/discovery_publish.rs", "std::ptr::eq(current.as_ref(), self)", "current.client_epoch == self.client_epoch", topology, "metric_discovery_diagnostic_epoch", "METRIC_DISCOVERY_ACTUAL_SET_IDENTITY", False),
            ("discovery-drop-keeps-authority", "control-topology/src/discovery_publish.rs", "impl Drop for DiscoveryPublisher {\n    fn drop(&mut self) {\n        self.revoke();", "impl Drop for DiscoveryPublisher {\n    fn drop(&mut self) {\n        // mutation: no revoke", topology, "metric_discovery_capture_original_owner", "METRIC_DISCOVERY_OWNER_OR_DROP", False),
            ("capture-range-not-fenced", "control-topology/src/discovery_publish.rs", ".fork_with_gate(self.set.gate.clone())", ".fork_with_gate(GenerationGate::new())", topology, "metric_discovery_capture_fences_held", "METRIC_DISCOVERY_NO_SECOND_PREFIX", False),
            ("applied-range-ignores-capture", "control-topology/src/discovery_publish.rs", ".fork_with_fence(fence)", ".fork()", topology, "metric_applied_capture_fences_etcd", "METRIC_APPLIED_RANGE_NO_SECOND_PREFIX", False),
            ("etcd-fork-drops-extra-fences", "control-external/src/etcd.rs", "additional_fence: self.additional_fence.clone()", "additional_fence: None", external, "metric_etcd_forks_preserve", "METRIC_ETCD_FORK_CONJUNCTION", False),
            ("transport-ignores-material-fence", "control-external/src/io_fence.rs", "self.first.is_live() && self.second.is_live()", "self.second.is_live()", external, "metric_either_fence_wins_dns_tls_and_body_failure", "METRIC_dns_FENCE", False),
            ("transport-ignores-work-fence", "control-external/src/io_fence.rs", "self.first.is_live() && self.second.is_live()", "self.first.is_live()", external, "metric_either_fence_wins_dns_tls_and_body_failure", "METRIC_dns_FENCE", False),
            ("actual-permit-does-not-fence-io", "control-etcd/src/authority.rs", "impl control_external::IoFence for ElectionWorkPermit {\n    fn is_live(&self) -> bool {\n        self.still_current()", "impl control_external::IoFence for ElectionWorkPermit {\n    fn is_live(&self) -> bool {\n        true", topology, live, "METRIC_ACTUAL_WORK_HTTP_FENCE", True),
            ("new-target-still-status", "control-external/src/cluster_http.rs", ".uri(target.as_str())", ".uri(STATUS_PATH)", external, "metric_target_preserves_explicit_dns", "METRIC_TARGET_WIRE", False),
        ]
        try:
            baseline()
            for name, path, before, after, package, test, required, ignored in cases:
                original = originals[path]
                expected = 2 if name in ["capture-range-not-fenced", "applied-range-ignores-capture", "etcd-fork-drops-extra-fences"] else 1
                if original.count(before) != expected:
                    raise RuntimeError(f"mutation anchor mismatch: {name}: {original.count(before)}")
                candidate = original.replace(before, after)
                if name == "capture-range-not-fenced":
                    candidate = candidate.replace(".fork_with_fence(fence)", ".fork()")
                if name == "late-material-withdrawal":
                    anchor = "            health.feeder.withdraw();\n            let discovery = self.discovery.commit(prepared);"
                    if candidate.count(anchor) != 1:
                        raise RuntimeError("late withdrawal insertion anchor mismatch")
                    candidate = candidate.replace(anchor, "            self.metrics.withdraw_material();\n" + anchor)
                (base / path).write_text(candidate)
                binary = compile_candidate(package)
                result = observe(binary, test, ignored)
                if result.returncode != 101 or required not in result.stdout or "test result: FAILED." not in result.stdout:
                    raise RuntimeError(f"mutation missed its required evidence: {name}\n{result.stdout}")
                (base / path).write_text(original)
                print(f"CP-METRIC-APPLIED compiling mutation killed: {name}", flush=True)
            baseline()
            print(f"CP-METRIC-APPLIED {len(cases)}/{len(cases)} compiling mutations killed; restored baseline passed", flush=True)
        finally:
            with http.open(urllib.request.Request(connection["control_url"] + "/release-cleanup", method="POST"), timeout=5):
                pass


if __name__ == "__main__":
    main()
