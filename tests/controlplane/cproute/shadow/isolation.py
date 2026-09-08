#!/usr/bin/env python3
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Guard the frozen value-only API and domain-to-legacy dependency boundary."""
from pathlib import Path
import re
import sys
import json
import subprocess

root = Path(sys.argv[1]).resolve()
shadow = root / 'rust/crates/control-router/src/shadow'
for path in shadow.glob('*.rs'):
    if path.name == 'tests.rs':
        continue
    source = path.read_text()
    forbidden = r'(?:\bcrate\s*::|\bsuper\s*::\s*super\b|control_proto::|control_config::ConfigNamespaceStore|control_topology::BackendSource|tokio::|std::(?:net|thread)|mpsc::)'
    if re.search(forbidden, source):
        raise SystemExit(f'SHADOW_NO_EFFECT_CAPABILITY: {path.name}')
metadata = json.loads(subprocess.check_output([
    'cargo', 'metadata', '--locked', '--offline', '--manifest-path',
    str(root / 'rust/Cargo.toml'), '--no-deps', '--format-version', '1'], text=True))
for package in metadata['packages']:
    if package['name'] not in ('control-router', 'control-routing', 'control-plane'):
        continue
    dependencies = {item['name'] for item in package['dependencies'] if item['kind'] != 'dev'}
    if {'control-proto', 'legacy-router-shadow'} & dependencies:
        raise SystemExit('SHADOW_NO_LEGACY_DOMAIN_DEPENDENCY: ' + package['name'])
print('CP-ROUTE shadow effect/API and legacy dependency isolation passed')
