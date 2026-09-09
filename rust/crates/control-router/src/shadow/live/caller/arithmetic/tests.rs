// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::*;

fn time(seconds: i64, nanos: u32, monotonic: Option<i64>) -> GoTime {
    GoTime::new(seconds, nanos, 1, monotonic).unwrap_or_else(|| unreachable!("fixture"))
}
fn next(rate: f64, arch: GoArch, same: bool, now: GoTime, last: GoTime) -> AfterClock {
    match start_value(rate, arch) {
        Start::ReadClock(rate) => rate.after_clock(same, now, last),
        Start::NoRate => unreachable!("nonzero fixture"),
    }
}
const fn scan(interval: i64, quota: i64) -> AfterClock {
    AfterClock::Scan { interval, quota }
}

#[test]
fn exact_signed_zero_returns_before_clock_and_pair() {
    for arch in [GoArch::Arm64, GoArch::Amd64] {
        for rate in [0.0, -0.0] {
            assert!(
                matches!(start_value(rate, arch), Start::NoRate),
                "CALLER_RATE_ZERO_NO_CLOCK"
            );
        }
        for rate in [-1.0, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert!(
                matches!(start_value(rate, arch), Start::ReadClock(_)),
                "CALLER_RATE_NONZERO_CONSUMES_CLOCK"
            );
        }
    }
}

#[test]
fn immutable_actual_go_probe_bits_match_both_producer_architectures() {
    // Original Go1.25.12 Group.Balance probes executed on M5 ARM64 and actual
    // AMD64 under Rosetta, frozen with contract v1.1. Inputs are controlled
    // policy outputs; these rows do not claim native-factor reachability.
    // Raw interval/quota expectations are arithmetic annotations accompanying
    // the recorded real offers/admissions/panics, not captured Go local values.
    let panic = AfterClock::DivideByZero;
    let cases = [
        (
            0xbff0_0000_0000_0000,
            scan(-1_000_000_000, 1),
            scan(-1_000_000_000, 1),
        ),
        (0xc415_af1d_78b5_8c40, panic, panic),
        (0x7ff8_0000_0000_0001, panic, scan(i64::MIN, 1)),
        (0x7ff0_0000_0000_0000, panic, panic),
        (0xfff0_0000_0000_0000, panic, panic),
        (0x4415_af1d_78b5_8c40, panic, panic),
        (
            0x41cd_cd65_0000_0000,
            scan(1, 10_000_000),
            scan(1, 10_000_000),
        ),
        (0x41cd_cd65_0000_0001, panic, panic),
        (0x01a5_6e1f_c2f8_f359, scan(i64::MAX, 1), scan(i64::MIN, 1)),
        (0x81a5_6e1f_c2f8_f359, scan(i64::MIN, 1), scan(i64::MIN, 1)),
        (
            0x4059_0000_0000_0000,
            scan(10_000_000, 1),
            scan(10_000_000, 1),
        ),
        (
            0x4049_0000_0000_0000,
            scan(20_000_000, 1),
            scan(20_000_000, 1),
        ),
    ];
    let now = time(63_000_000_000, 0, None);
    let zero = time(0, 0, None);
    for (bits, arm, amd) in cases {
        for (arch, expected) in [(GoArch::Arm64, arm), (GoArch::Amd64, amd)] {
            assert_eq!(
                next(f64::from_bits(bits), arch, true, now, zero),
                expected,
                "CALLER_GO_PROBE_MATRIX {arch:?} {bits:016x}"
            );
        }
    }
}

#[test]
fn producer_architecture_controls_nan_and_duration_overflow() {
    let now = time(63_000_000_000, 0, None);
    let zero = time(0, 0, None);
    assert_eq!(
        next(f64::NAN, GoArch::Arm64, true, now, zero),
        AfterClock::DivideByZero,
        "CALLER_GO_ARCH_ARM_NAN"
    );
    assert_eq!(
        next(f64::NAN, GoArch::Amd64, true, now, zero),
        scan(i64::MIN, 1),
        "CALLER_GO_ARCH_AMD_NAN"
    );
    let tiny = f64::from_bits(0x01a5_6e1f_c2f8_f359);
    assert_eq!(
        next(tiny, GoArch::Arm64, true, now, zero),
        scan(i64::MAX, 1),
        "CALLER_GO_SUB_SATURATES"
    );
    assert_eq!(
        next(tiny, GoArch::Amd64, true, now, zero),
        scan(i64::MIN, 1),
        "CALLER_GO_ARCH_AMD_OVERFLOW"
    );
}

#[test]
fn interval_zero_is_abnormal_and_pair_refusal_precedes_conversion() {
    let now = time(63_000_000_000, 0, None);
    for arch in [GoArch::Arm64, GoArch::Amd64] {
        for rate in [
            1e20,
            -1e20,
            f64::INFINITY,
            f64::NEG_INFINITY,
            f64::from_bits(0x41cd_cd65_0000_0001),
        ] {
            assert_eq!(
                next(rate, arch, true, now, now),
                AfterClock::DivideByZero,
                "CALLER_ZERO_INTERVAL_MUST_BE_ABNORMAL"
            );
            assert_eq!(
                next(rate, arch, false, now, now),
                AfterClock::CrossKeyspace,
                "CALLER_PAIR_REFUSAL_PRECEDES_CAST"
            );
        }
    }
}

#[test]
fn raw_signed_quota_has_no_rounding_or_physical_population_clamp() {
    let now = time(63_000_000_000, 0, None);
    for arch in [GoArch::Arm64, GoArch::Amd64] {
        assert_eq!(
            next(1e9, arch, true, now, now),
            scan(1, 10_000_000),
            "CALLER_RAW_QUOTA_NOT_PHYSICAL_CAP"
        );
        assert_eq!(
            next(-1e9, arch, true, now, now),
            scan(-1, -9_999_998),
            "CALLER_QUOTA_SIGNED_DIVISION"
        );
        assert_eq!(
            next(1e9 / 1.9, arch, true, now, now),
            scan(1, 10_000_000),
            "CALLER_INTERVAL_TRUNCATES"
        );
    }
}

#[test]
fn exact_twice_tick_uses_slow_branch_and_elapsed_equality_is_eligible() {
    let last = time(63_000_000_000, 0, Some(100_000_000));
    for arch in [GoArch::Arm64, GoArch::Amd64] {
        let early = time(63_000_000_005, 0, Some(119_999_999));
        assert_eq!(
            next(50.0, arch, true, early, last),
            AfterClock::Wait {
                interval: 20_000_000
            },
            "CALLER_TWICE_TICK_SLOW_MONOTONIC"
        );
        let equal = time(63_000_000_005, 0, Some(120_000_000));
        assert_eq!(
            next(50.0, arch, true, equal, last),
            scan(20_000_000, 1),
            "CALLER_ELAPSED_EQUAL_ELIGIBLE"
        );
        // A rate one ULP above 50 changes the discrete interval and must not be
        // repaired by tolerance or by copying Go's captured quota/rate.
        let fast = f64::from_bits(50_f64.to_bits() + 1);
        assert_eq!(
            next(fast, arch, true, last, last),
            scan(19_999_999, 1),
            "CALLER_DISCRETE_RATE_BOUNDARY"
        );
    }
}

#[test]
fn zero_watermark_cannot_distinguish_rate_boundary_by_offer_quota() {
    let now = time(63_000_000_000, 0, None);
    let zero = time(0, 0, None);
    for arch in [GoArch::Arm64, GoArch::Amd64] {
        let exact = next(50.0, arch, true, now, zero);
        let perturbed = next(f64::from_bits(50_f64.to_bits() + 1), arch, true, now, zero);
        assert_eq!(exact, scan(20_000_000, 1));
        assert_eq!(perturbed, scan(19_999_999, 1));
        // Both examine the list with quota=1. Observing one offered redirect
        // at a zero watermark cannot detect substitution of the scalar rate.
        assert!(
            matches!(exact, AfterClock::Scan { quota: 1, .. })
                && matches!(perturbed, AfterClock::Scan { quota: 1, .. }),
            "CALLER_ZERO_WATERMARK_SAME_OFFER_QUOTA"
        );
    }
}

fn native_rate_fixture() -> (
    crate::shadow::live::LiveState,
    crate::shadow::native::Evaluation,
    crate::shadow::native::Evaluation,
) {
    use crate::shadow::{
        Event, Limits,
        native::{Advice, Entry},
    };
    let (mut state, mut configuration) = super::super::tests::setup(Limits::default());
    let epoch = configuration.epoch;
    let ledger = &mut state
        .core
        .owners
        .get_mut(&(epoch.process, epoch.owner))
        .unwrap_or_else(|| unreachable!("owner"))
        .ledger;
    assert!(ledger.apply(&Event::Account { id: 19, group: 2 }).is_ok());
    for session in 10..13 {
        assert!(
            ledger
                .apply(&Event::Rehydrate {
                    session,
                    account: 9
                })
                .is_ok()
        );
    }
    let mut evaluation = configuration.clone();
    configuration.config += 1;
    configuration.configuration.rates[0] = 1_f64.to_bits();
    configuration.configuration.rates[5] = 50_f64.to_bits();
    configuration.entry = Entry::Config;
    configuration.accounts.clear();
    configuration.reads.clear();
    configuration.sorted.clear();
    configuration.returned.clear();
    evaluation.config = configuration.config;
    evaluation.configuration = configuration.configuration.clone();
    evaluation.sequence = 6;
    evaluation.evaluation = 3;
    evaluation.entry = Entry::Balance;
    let mut destination = evaluation.accounts[0].clone();
    destination.account = 19;
    destination.id = "destination".into();
    destination.addr = "destination:4000".into();
    evaluation.accounts[0].physical = 3;
    evaluation.accounts[0].score_count = 3;
    evaluation.accounts[0].parts[1] = 3;
    evaluation.accounts[0].packed = 3;
    evaluation.accounts[0].routeability_seen = false;
    evaluation.accounts[0].routeable = false;
    evaluation.accounts.push(destination);
    evaluation.sorted = vec![1, 0];
    evaluation.returned.clear();
    evaluation.from = 0;
    evaluation.to = 1;
    evaluation.reason = Some(crate::Factor::Connection);
    evaluation.balance_count = 50_f64.to_bits() + 1;
    evaluation.advice = vec![
        Advice {
            from: 0,
            to: 1,
            factor: crate::Factor::Status,
            advice: 2,
            count: 1_f64.to_bits(),
        },
        Advice {
            from: 0,
            to: 1,
            factor: crate::Factor::Connection,
            advice: 2,
            count: evaluation.balance_count,
        },
    ];
    (state, configuration, evaluation)
}

#[test]
fn tolerated_native_rate_witness_cannot_replace_independent_caller_rate() {
    use super::super::Scope;
    use crate::shadow::{InvalidReason, Status, native::Entry};
    let (mut state, configuration, evaluation) = native_rate_fixture();
    let epoch = configuration.epoch;
    let original = state.native_retained_bytes();
    let mut transaction = state
        .begin_caller(Scope {
            epoch,
            group: 2,
            sequence: 5,
            span: 3,
            sessions: &[10, 11, 12],
            frame_bytes: 4096,
        })
        .unwrap_or_else(|e| unreachable!("{e:?}"));
    let configured = transaction
        .evaluation(&configuration)
        .unwrap_or_else(|e| unreachable!("{e:?}"));
    assert!(
        configured.balance_rate().is_none(),
        "CALLER_CONFIG_IS_NOT_BALANCE_RATE"
    );
    let decision = transaction
        .evaluation(&evaluation)
        .unwrap_or_else(|e| unreachable!("{e:?}"));
    assert_eq!(decision.pair(), (0, 1, Some(crate::Factor::Connection)));
    assert!(decision.returned().is_empty());
    assert_eq!(decision.entry(), Entry::Balance);
    let now = time(63_000_000_000, 0, None);
    // A recent NONZERO watermark is essential: no elapsed time means exact
    // 50/s waits, while 50+1ULP takes the fast branch regardless of watermark.
    let independent = match start(
        decision
            .balance_rate()
            .unwrap_or_else(|| unreachable!("balance")),
        GoArch::Arm64,
    ) {
        Start::ReadClock(rate) => rate.after_clock(true, now, now),
        Start::NoRate => unreachable!("positive independent rate"),
    };
    // This deliberately forged caller result matches the slightly perturbed
    // Go scalar witness. It differs discretely from the independent native50/s
    // result even though the legacy scalar comparison accepts the perturbation.
    let forged_caller_result = scan(19_999_999, 1);
    let final_check = if independent == forged_caller_result {
        Ok(())
    } else {
        Err(InvalidReason::Witness)
    };
    let progress = transaction.finish(final_check);
    assert_eq!(
        (progress.status, progress.compared_sequence),
        (Status::Invalid(InvalidReason::Witness), 4),
        "CALLER_FINAL_REJECTS_TOLERATED_RATE_SUBSTITUTION"
    );
    assert_eq!(state.native_retained_bytes(), original);
}
