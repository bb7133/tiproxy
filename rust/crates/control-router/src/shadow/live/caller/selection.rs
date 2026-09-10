// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Bounded Go BackendSelector.Next transitions. Inputs must be independently
//! derived routeOnce results, never the observed return values being checked.
//! This component has no factory, wire dispatch, ledger or effect capability.
use super::InvalidReason;

/// The exclusion limit is diagnostic only; Go must keep running on overflow.
pub const MAX_EXCLUDED: usize = 64;

/// Original reservation binding supplied by a verified routeOnce comparison.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Binding {
    /// Backend incarnation, also used in the selector's exclusion history.
    pub account: u64,
    /// Group that accepted this reservation, not the router's later group.
    pub group: u64,
    /// Original reservation operation.
    pub operation: u64,
}
impl Binding {
    fn valid(self) -> bool {
        self.account != 0 && self.group != 0 && self.operation != 0
    }
}

/// Error equality as used by Next. Wrapped `ErrNoBackend` is Other, even though
/// the separate router refresh effect uses errors.Is. Error text is not input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorClass {
    /// Successful call.
    None,
    /// The exact `ErrNoBackend` singleton, regardless of its origin.
    NoBackend,
    /// Any other error, including a wrapper around `ErrNoBackend`.
    Other,
}

/// A result already derived by a routeOnce comparator. Error returns preserve
/// the backend value independently from the retained successful binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DerivedResult {
    /// Backend returned by the call; zero denotes nil.
    pub backend: u64,
    /// Exact equality class of the returned error.
    pub error: ErrorClass,
    /// Present exactly for success, and bound to the returned account.
    pub binding: Option<Binding>,
}
impl DerivedResult {
    fn valid(self) -> bool {
        match (self.error, self.binding) {
            (ErrorClass::None, Some(binding)) => binding.valid() && self.backend == binding.account,
            (ErrorClass::NoBackend | ErrorClass::Other, None) => true,
            _ => false,
        }
    }
}

/// Output expected from the next source branch, not a routing command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Continue {
    /// Clear exclusions and execute exactly one further routeOnce call.
    Retry,
    /// Return the last call's actual backend/error.
    Return,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct State {
    excluded: [u64; MAX_EXCLUDED],
    count: usize,
    current: Option<Binding>,
}
impl Default for State {
    fn default() -> Self {
        Self {
            excluded: [0; MAX_EXCLUDED],
            count: 0,
            current: None,
        }
    }
}
impl State {
    fn excluded(&self) -> &[u64] {
        &self.excluded[..self.count]
    }
    fn current(&self) -> u64 {
        self.current.map_or(0, |binding| binding.account)
    }
}

#[derive(Clone)]
struct Open {
    next: u64,
    attempts: u8,
    working: State,
    returned: Option<DerivedResult>,
}

/// Fixed retained selector state and one open Next. All state changes are
/// staged until its completion witness matches. A failure is sticky and leaves
/// the last completed state intact. Integration must charge CHARGE in shared R
/// before retaining each instance, and feed only independently checked attempts.
/// This is not yet installed in `LiveState` or the production caller transport.
#[derive(Default)]
pub struct Tracker {
    last_next: u64,
    state: State,
    open: Option<Open>,
    failed: Option<InvalidReason>,
}
impl Tracker {
    /// Full fixed storage, including the temporary Next state and exclusion list.
    pub const CHARGE: usize = size_of::<Self>();

    /// Last completed exclusion order. Duplicate accounts are not normalized:
    /// Go appends exactly what a successful call returned.
    #[must_use]
    pub fn excluded(&self) -> &[u64] {
        self.state.excluded()
    }
    /// Original last-success binding; errors never overwrite it.
    #[must_use]
    pub const fn current(&self) -> Option<Binding> {
        self.state.current
    }
    /// Open one contiguous Next ordinal with the actual pre-call witnesses.
    ///
    /// # Errors
    /// Sticky replay, overlap or state-witness mismatch.
    pub fn begin(
        &mut self,
        next: u64,
        current: u64,
        excluded: &[u64],
    ) -> Result<(), InvalidReason> {
        let result = self.check().and_then(|()| {
            if self.open.is_some() {
                return Err(InvalidReason::Lifecycle);
            }
            if self.last_next.checked_add(1) != Some(next) {
                return Err(InvalidReason::Sequence);
            }
            if current != self.state.current() || excluded != self.state.excluded() {
                return Err(InvalidReason::Witness);
            }
            Ok(())
        });
        self.remember(result)?;
        self.open = Some(Open {
            next,
            attempts: 0,
            working: self.state.clone(),
            returned: None,
        });
        Ok(())
    }
    /// Consume one independently derived attempt, checking its original input
    /// exclusions and ordinal. Two calls are allowed only for the exact first
    /// sentinel with nonempty exclusions; the second result never retries.
    ///
    /// # Errors
    /// Sticky malformed result, missing/repeated attempt, capacity or witness failure.
    pub fn attempt(
        &mut self,
        next: u64,
        ordinal: u8,
        excluded: &[u64],
        derived: DerivedResult,
    ) -> Result<Continue, InvalidReason> {
        let result = self.check().and_then(|()| {
            let open = self.open.as_ref().ok_or(InvalidReason::Lifecycle)?;
            if open.next != next {
                return Err(InvalidReason::Identity);
            }
            if open.returned.is_some() || ordinal != open.attempts + 1 || ordinal > 2 {
                return Err(InvalidReason::Sequence);
            }
            if excluded != open.working.excluded() || !derived.valid() {
                return Err(InvalidReason::Witness);
            }
            let mut working = open.working.clone();
            let retry =
                ordinal == 1 && derived.error == ErrorClass::NoBackend && working.count != 0;
            if retry {
                working.excluded.fill(0);
                working.count = 0;
            } else if derived.error == ErrorClass::None {
                if working.count == MAX_EXCLUDED {
                    return Err(InvalidReason::Capacity);
                }
                working.current = derived.binding;
                working.excluded[working.count] = derived.backend;
                working.count += 1;
            }
            Ok((working, retry))
        });
        let (working, retry) = match result {
            Ok(value) => value,
            Err(reason) => {
                self.remember(Err(reason))?;
                return Err(reason);
            }
        };
        if let Some(open) = self.open.as_mut() {
            open.working = working;
            open.attempts = ordinal;
            if !retry {
                open.returned = Some(derived);
            }
        }
        Ok(if retry {
            Continue::Retry
        } else {
            Continue::Return
        })
    }
    /// Compare the actual Next return and post-call state before committing.
    /// An ordinary error retains current/exclusions; an error after the single
    /// retry retains current but preserves the already-cleared exclusions.
    ///
    /// # Errors
    /// Sticky incomplete Next, ordinal, return, current or exclusion mismatch.
    pub fn end(
        &mut self,
        next: u64,
        backend: u64,
        error: ErrorClass,
        current: u64,
        excluded: &[u64],
    ) -> Result<(), InvalidReason> {
        let result = self.check().and_then(|()| {
            let open = self.open.as_ref().ok_or(InvalidReason::Lifecycle)?;
            if open.next != next {
                return Err(InvalidReason::Identity);
            }
            let returned = open.returned.ok_or(InvalidReason::Lifecycle)?;
            if (backend, error) != (returned.backend, returned.error)
                || current != open.working.current()
                || excluded != open.working.excluded()
            {
                return Err(InvalidReason::Witness);
            }
            Ok(())
        });
        self.remember(result)?;
        if let Some(open) = self.open.take() {
            self.last_next = open.next;
            self.state = open.working;
        }
        Ok(())
    }
    /// Check the backend actually passed to Finish and return its original
    /// binding for the separate lifecycle comparator. This method creates no
    /// reservation/refund and does not validate Created or Close lifetimes.
    ///
    /// # Errors
    /// Sticky missing current, open Next or wrong backend.
    pub fn finish_binding(&mut self, backend: u64) -> Result<Binding, InvalidReason> {
        let result = self.check().and_then(|()| {
            if self.open.is_some() {
                return Err(InvalidReason::Lifecycle);
            }
            self.state
                .current
                .filter(|binding| binding.account == backend)
                .ok_or(InvalidReason::Witness)
        });
        if let Err(reason) = result {
            self.remember(Err(reason))?;
        }
        result
    }
    /// A final compared tail cannot contain an unfinished Next.
    ///
    /// # Errors
    /// Returns the sticky failure or an open-call error, without repairing state.
    pub fn tail(&self) -> Result<(), InvalidReason> {
        self.check()?;
        if self.open.is_some() {
            Err(InvalidReason::Lifecycle)
        } else {
            Ok(())
        }
    }
    fn check(&self) -> Result<(), InvalidReason> {
        self.failed.map_or(Ok(()), Err)
    }
    fn remember(&mut self, result: Result<(), InvalidReason>) -> Result<(), InvalidReason> {
        if let Err(reason) = result {
            self.failed.get_or_insert(reason);
        }
        result
    }
}

#[cfg(test)]
mod tests;
