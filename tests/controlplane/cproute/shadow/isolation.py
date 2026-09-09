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
for path in shadow.rglob('*.rs'):
    if path.name == 'tests.rs' or path.name.endswith('_tests.rs'):
        continue
    source = path.read_text()
    # Explicit value-only imports into the native comparer. An added Router,
    # ledger owner, candidate or command import remains forbidden. The two
    # shared phase modules are scanned independently below.
    allowed = {
        'native.rs': [r'use crate::Factor;', r'pub use crate::factors::window::\{ClockSite, GoArch\};'],
        'native_compute.rs': [
            r'use crate::factors::window::\{self, Backend, Count, Query, Time, Window\};',
            r'use crate::factors::\{order, phases\};',
            r'use crate::\{BalanceAdvice, Factor, FactorAdvice, FactorScore\};',
        ],
    }
    for statement in allowed.get(path.name, []):
        source = re.sub(statement, '', source)
    if path.relative_to(shadow).as_posix() == 'live/native.rs':
        source = source.replace('use super::super::native::{Coverage, Evaluation, FactorState};', '')
    forbidden = r'(?:\bcrate\s*::|\bsuper\s*::\s*super\b|control_proto::|control_config::ConfigNamespaceStore|control_topology::BackendSource|tokio::|std::(?:net|thread)|mpsc::)'
    if re.search(forbidden, source):
        raise SystemExit(f'SHADOW_NO_EFFECT_CAPABILITY: {path.name}')
for name in ['window.rs', 'phases.rs']:
    path = root / 'rust/crates/control-router/src/factors' / name
    source = path.read_text()
    if re.search(r'AccountIdentity|ResourceIncarnation|CommandQueue|(?:crate|super)::(?:ledger|selector|Router)|control_proto::|tokio::|std::(?:net|thread)', source):
        raise SystemExit('SHADOW_SHARED_PHASE_AUTHORITY: ' + name)
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
