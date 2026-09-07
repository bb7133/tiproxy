// Copyright 2026 PingCAP, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! One connection's retry cycle; attempts retain exact ledger authority.

use crate::{Candidate, Reservation, RouteError, Router, Session, Settlement};
use control_routing::group::ClientInfo;
use std::sync::Arc;

/// A connection-scoped selector. Failed attempts remain excluded until a route
/// returns `NoBackend`; that condition clears the cycle and tries once more.
/// Port conflicts and source/admission failures preserve the cycle. Dropping
/// this value closes its session, including any pending or active reservation.
pub struct Selector {
    router: Arc<Router>,
    session: Session,
    excluded: Vec<String>,
}

impl Router {
    /// Opens a connection-scoped retry selector on this exact router.
    ///
    /// # Errors
    /// Returns the same admission/capacity errors as [`Router::open`].
    pub fn selector(self: &Arc<Self>) -> Result<Selector, RouteError> {
        Ok(Selector {
            router: Arc::clone(self),
            session: self.open()?,
            excluded: Vec::new(),
        })
    }
}

impl Selector {
    #[cfg(test)]
    pub(crate) fn exclusions(&self) -> &[String] {
        &self.excluded
    }

    /// Captures current sources and reserves the next attempt. An unsettled
    /// pending attempt is retransmitted without charging or excluding twice.
    ///
    /// # Errors
    /// Returns capture/reserve failures; only `NoBackend` resets exclusions.
    pub fn next(
        &mut self,
        client: ClientInfo<'_>,
        listener_port: &str,
    ) -> Result<Reservation, RouteError> {
        let candidate = self.router.capture()?;
        self.next_candidate(&candidate, client, listener_port)
    }

    pub(crate) fn next_candidate(
        &mut self,
        candidate: &Candidate,
        client: ClientInfo<'_>,
        listener_port: &str,
    ) -> Result<Reservation, RouteError> {
        let excluded: Vec<&str> = self.excluded.iter().map(String::as_str).collect();
        let mut result =
            self.router
                .reserve(&self.session, candidate, client, listener_port, &excluded);
        if matches!(result, Err(RouteError::NoBackend)) && !self.excluded.is_empty() {
            self.excluded.clear();
            result = self
                .router
                .reserve(&self.session, candidate, client, listener_port, &[]);
        }
        if let Ok(reservation) = &result {
            let id = &reservation.assignment().backend_id;
            if !self.excluded.contains(id) {
                self.excluded.push(id.clone());
            }
        }
        result
    }

    /// Settles the supplied exact attempt, never the latest selected backend.
    /// Late/duplicate/foreign results are ignored by the owning ledger.
    #[must_use]
    pub fn finish(&self, reservation: &Reservation, connected: bool) -> Settlement {
        if !reservation.belongs_to(&self.session) {
            return Settlement::Ignored;
        }
        self.router.finish(reservation, connected)
    }
}

impl Drop for Selector {
    fn drop(&mut self) {
        self.router.close(&self.session);
    }
}
