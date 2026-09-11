// Copyright 2026 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::{Decimal, Epoch, Error, finish};
use crate::live::NestedBatch;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireFinish {
    caller: Decimal,
    group: Decimal,
    session: Decimal,
    backend: Decimal,
    operation: Decimal,
    success: bool,
    created: NestedBatch,
}
impl WireFinish {
    pub(super) fn domain(
        self,
        epoch: Epoch,
        sequence: u64,
        span: u64,
    ) -> Result<finish::Envelope, Error> {
        let envelope = finish::Envelope {
            epoch,
            sequence,
            span,
            caller: self.caller.0,
            group: self.group.0,
            session: self.session.0,
            backend: self.backend.0,
            operation: self.operation.0,
            success: self.success,
            created: self.created.domain()?,
        };
        envelope.validate().map_err(|_| Error::Schema)?;
        Ok(envelope)
    }
}
