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

//! Builds a `rustls::ClientConfig` for the etcd transport from validated TLS
//! material and policy.
//!
//! This is a neutral, in-crate implementation of the frozen `cluster-tls`
//! verification semantics, so `control-external` does not depend on any
//! dataplane crate. The verifier composes a single outer
//! [`ServerCertVerifier`]:
//!
//! | `skip_ca` | common names | server certificate verification |
//! |-----------|--------------|---------------------------------|
//! | false     | empty        | `WebPKI` chain + hostname |
//! | false     | non-empty    | `WebPKI` chain + hostname, then exact leaf Subject-CN pin |
//! | true      | empty        | chain/hostname skipped, TLS `CertificateVerify` signature still checked |
//! | true      | non-empty    | as above, then exact leaf Subject-CN pin |
//!
//! The minimum protocol version is always frozen explicitly (`1.2` and the
//! default select `[TLS1.2, TLS1.3]`; `1.3` selects `[TLS1.3]`), so a rustls
//! upgrade cannot silently change the wire protocol set. Client mTLS material,
//! when present, is parsed here from the generation-bound bytes.

use std::collections::BTreeSet;
use std::sync::Arc;

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};

use crate::etcd::{EtcdConfigError, EtcdTlsPolicy, EtcdTlsVersion};

/// Builds the client TLS configuration for one etcd connection from its CA
/// bundle, optional client identity, and verification policy.
///
/// # Errors
///
/// Returns [`EtcdConfigError::TlsSetup`] when the material cannot form a client
/// configuration (unparseable PEM, a client chain whose key does not match, an
/// empty trust anchor when CA verification is required, or an unusable rustls
/// build).
pub(crate) fn build_client_config(
    ca_certificate_pem: Option<&[u8]>,
    identity: Option<(&[u8], &[u8])>,
    policy: &EtcdTlsPolicy,
) -> Result<Arc<ClientConfig>, EtcdConfigError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    // Freeze the protocol set explicitly for every case.
    let versions: &[&rustls::SupportedProtocolVersion] = match policy.minimum_version {
        Some(EtcdTlsVersion::V1_3) => &[&rustls::version::TLS13],
        None | Some(EtcdTlsVersion::V1_2) => &[&rustls::version::TLS12, &rustls::version::TLS13],
    };
    let builder = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(versions)
        .map_err(|_| EtcdConfigError::TlsSetup)?;

    let verifier = build_server_verifier(&provider, ca_certificate_pem, policy)?;
    let builder = builder
        .dangerous()
        .with_custom_certificate_verifier(verifier);

    let config = match identity {
        Some((certificate_pem, key_pem)) => {
            let chain = parse_certificate_chain(certificate_pem)?;
            let key = parse_private_key(key_pem)?;
            builder
                .with_client_auth_cert(chain, key)
                .map_err(|_| EtcdConfigError::TlsSetup)?
        }
        None => builder.with_no_client_auth(),
    };
    Ok(Arc::new(config))
}

/// Composes the single outer server-certificate verifier per the truth table.
fn build_server_verifier(
    provider: &Arc<CryptoProvider>,
    ca_certificate_pem: Option<&[u8]>,
    policy: &EtcdTlsPolicy,
) -> Result<Arc<dyn ServerCertVerifier>, EtcdConfigError> {
    let inner: Arc<dyn ServerCertVerifier> = if policy.skip_ca_verification {
        Arc::new(SkipServerVerification::new(Arc::clone(provider)))
    } else {
        let ca = ca_certificate_pem.ok_or(EtcdConfigError::EmptyCaCertificate)?;
        let mut roots = RootCertStore::empty();
        for certificate in CertificateDer::pem_slice_iter(ca) {
            let certificate = certificate.map_err(|_| EtcdConfigError::TlsSetup)?;
            roots
                .add(certificate)
                .map_err(|_| EtcdConfigError::TlsSetup)?;
        }
        if roots.is_empty() {
            return Err(EtcdConfigError::EmptyCaCertificate);
        }
        WebPkiServerVerifier::builder_with_provider(Arc::new(roots), Arc::clone(provider))
            .build()
            .map_err(|_| EtcdConfigError::TlsSetup)?
    };
    if policy.allowed_common_names.is_empty() {
        return Ok(inner);
    }
    Ok(Arc::new(CommonNamePinnedServerVerifier {
        inner,
        allowed_common_names: policy.allowed_common_names.iter().cloned().collect(),
    }))
}

/// Parses a client certificate chain from PEM into owned DER.
fn parse_certificate_chain(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, EtcdConfigError> {
    let mut chain = Vec::new();
    for certificate in CertificateDer::pem_slice_iter(pem) {
        chain.push(
            certificate
                .map_err(|_| EtcdConfigError::TlsSetup)?
                .into_owned(),
        );
    }
    if chain.is_empty() {
        return Err(EtcdConfigError::TlsSetup);
    }
    Ok(chain)
}

/// Parses the first private key from PEM into an owned key.
fn parse_private_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>, EtcdConfigError> {
    let key = PrivateKeyDer::pem_slice_iter(pem)
        .next()
        .ok_or(EtcdConfigError::TlsSetup)?
        .map_err(|_| EtcdConfigError::TlsSetup)?;
    Ok(key.clone_key())
}

/// Skips certificate-chain and hostname trust while still validating the
/// handshake `CertificateVerify` signature against the presented certificate,
/// mirroring Go `skip-ca` exactly (the peer must still hold the key).
#[derive(Debug)]
struct SkipServerVerification {
    provider: Arc<CryptoProvider>,
}

impl SkipServerVerification {
    fn new(provider: Arc<CryptoProvider>) -> Self {
        Self { provider }
    }
}

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Wraps an inner server-certificate verifier and additionally pins the leaf
/// certificate's Subject common name to an exact allowlist. `skip_ca` does not
/// short-circuit this pin.
#[derive(Debug)]
struct CommonNamePinnedServerVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    allowed_common_names: BTreeSet<String>,
}

impl ServerCertVerifier for CommonNamePinnedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let verified = self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;
        let (_, certificate) = x509_parser::prelude::parse_x509_certificate(end_entity.as_ref())
            .map_err(|_| rustls::Error::General("server certificate is unparseable".to_owned()))?;
        let allowed = certificate.subject().iter_common_name().any(|name| {
            name.as_str()
                .is_ok_and(|value| self.allowed_common_names.contains(value))
        });
        if !allowed {
            return Err(rustls::Error::General(
                "server certificate common name is not allowed".to_owned(),
            ));
        }
        Ok(verified)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::{CommonNamePinnedServerVerifier, build_client_config};
    use crate::etcd::{EtcdConfigError, EtcdTlsPolicy, EtcdTlsVersion};
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
    use std::sync::Arc;

    /// A self-signed certificate and its private key, both PEM.
    fn certificate_with_common_name(common_name: &str) -> (String, String) {
        let mut params = rcgen::CertificateParams::new(vec!["example.com".to_owned()])
            .unwrap_or_else(|error| unreachable!("params: {error}"));
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, common_name);
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let key = rcgen::KeyPair::generate().unwrap_or_else(|error| unreachable!("key: {error}"));
        let certificate = params
            .self_signed(&key)
            .unwrap_or_else(|error| unreachable!("self-signed: {error}"));
        (certificate.pem(), key.serialize_pem())
    }

    fn policy(skip: bool, common_names: &[&str], version: Option<EtcdTlsVersion>) -> EtcdTlsPolicy {
        EtcdTlsPolicy {
            minimum_version: version,
            allowed_common_names: common_names.iter().map(|name| (*name).to_owned()).collect(),
            skip_ca_verification: skip,
        }
    }

    #[test]
    fn every_verifier_row_and_version_builds() {
        let (ca, _) = certificate_with_common_name("etcd-ca");
        for version in [None, Some(EtcdTlsVersion::V1_2), Some(EtcdTlsVersion::V1_3)] {
            // Row 1 + 2: verify against CA, with and without CN pins.
            assert!(
                build_client_config(Some(ca.as_bytes()), None, &policy(false, &[], version))
                    .is_ok()
            );
            assert!(
                build_client_config(
                    Some(ca.as_bytes()),
                    None,
                    &policy(false, &["etcd"], version)
                )
                .is_ok()
            );
            // Row 3 + 4: skip CA (no CA needed), with and without CN pins.
            assert!(build_client_config(None, None, &policy(true, &[], version)).is_ok());
            assert!(build_client_config(None, None, &policy(true, &["etcd"], version)).is_ok());
        }
    }

    #[test]
    fn ca_verification_requires_a_ca_but_skip_does_not() {
        // skip=false with no CA fails closed; skip=true with no CA is fine.
        assert_eq!(
            build_client_config(None, None, &policy(false, &[], None)).err(),
            Some(EtcdConfigError::EmptyCaCertificate)
        );
        assert!(build_client_config(None, None, &policy(true, &[], None)).is_ok());
    }

    #[test]
    fn client_identity_parsing_is_discriminating() {
        let (ca, _) = certificate_with_common_name("etcd-ca");
        let (client_cert, client_key) = certificate_with_common_name("etcd-client");
        // A matched chain and key builds.
        assert!(
            build_client_config(
                Some(ca.as_bytes()),
                Some((client_cert.as_bytes(), client_key.as_bytes())),
                &policy(false, &[], None),
            )
            .is_ok()
        );
        // Malformed certificate PEM, malformed key PEM, and a mismatched
        // certificate/key pair all fail closed.
        assert!(
            build_client_config(
                Some(ca.as_bytes()),
                Some((b"not-a-cert", client_key.as_bytes())),
                &policy(false, &[], None),
            )
            .is_err()
        );
        assert!(
            build_client_config(
                Some(ca.as_bytes()),
                Some((client_cert.as_bytes(), b"not-a-key")),
                &policy(false, &[], None),
            )
            .is_err()
        );
        let (_, other_key) = certificate_with_common_name("someone-else");
        assert!(
            build_client_config(
                Some(ca.as_bytes()),
                Some((client_cert.as_bytes(), other_key.as_bytes())),
                &policy(false, &[], None),
            )
            .is_err()
        );
    }

    /// An inner verifier that accepts every certificate, so the test isolates
    /// the common-name pin.
    #[derive(Debug)]
    struct AcceptAll;

    impl ServerCertVerifier for AcceptAll {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            Vec::new()
        }
    }

    #[test]
    fn common_name_pin_accepts_only_the_allowlisted_cn() {
        let (pinned_pem, _) = certificate_with_common_name("pinned-cn");
        let pinned = CertificateDer::from_pem_slice(pinned_pem.as_bytes())
            .unwrap_or_else(|error| unreachable!("parse: {error}"));
        let server_name = ServerName::try_from("example.com").unwrap_or_else(|_| unreachable!());
        let now = UnixTime::now();

        let allowed = CommonNamePinnedServerVerifier {
            inner: Arc::new(AcceptAll),
            allowed_common_names: ["pinned-cn".to_owned()].into_iter().collect(),
        };
        assert!(
            allowed
                .verify_server_cert(&pinned, &[], &server_name, &[], now)
                .is_ok(),
            "a certificate whose CN is allowlisted passes"
        );

        let rejected = CommonNamePinnedServerVerifier {
            inner: Arc::new(AcceptAll),
            allowed_common_names: ["other-cn".to_owned()].into_iter().collect(),
        };
        assert!(
            rejected
                .verify_server_cert(&pinned, &[], &server_name, &[], now)
                .is_err(),
            "a certificate whose CN is not allowlisted is rejected even though the inner verifier accepted it"
        );
    }
}
