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
    # Exact complete lines, scoped to their precise source path. Adding Router,
    # production ledger owners, candidates or commands to any import still fails
    # the unchanged prohibition below; a same-named file inherits no exception.
    allowed = {
        'native.rs': [
            'use crate::Factor;',
            'pub use crate::factors::window::{ClockSite, GoArch};',
        ],
        'native_compute.rs': [
            'use crate::factors::window::{self, Backend, Count, Query, Time, Window};',
            'use crate::factors::{order, phases};',
            'use crate::{BalanceAdvice, Factor, FactorAdvice, FactorScore};',
        ],
        'live/native.rs': [
            'use super::super::native::{Coverage, Decision, Evaluation, FactorState};',
        ],
        'live/caller.rs': [
            'use crate::shadow::native::{Decision, Evaluation};',
            # This literal constructs the private shadow mirror owner, with only
            # copied ledger/history values. It is not a production ledger owner.
            'crate::shadow::Owner {',
        ],
        'live/caller/arithmetic.rs': [
            'use crate::shadow::native::{BalanceRate, GoArch};',
        ],
        'live/caller/balance.rs': [
            'use crate::shadow::native::{Entry, Evaluation};',
        ],
        'live/caller/pass.rs': [
            'use crate::shadow::{Epoch, InvalidReason};',
        ],
        'live/caller/route.rs': [
            'use crate::shadow::native::{Entry, Evaluation};',
        ],
    }
    statements = allowed.get(path.relative_to(shadow).as_posix(), [])
    source = '\n'.join('' if line.strip() in statements else line
                       for line in source.splitlines())
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
