use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::sync::Arc;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tracing::{debug, info, warn};
use x509_parser::prelude::*;

use crate::Allowlist;

#[derive(Clone)]
struct StoredCert {
    certified_key: Arc<CertifiedKey>,
    not_before: i64,
    secret_key: String,
}

/// Stores parsed TLS certificates indexed by exact hostname and wildcard suffix.
#[derive(Default)]
pub struct CertStore {
    allowlist: HashSet<String>,
    exact: HashMap<String, StoredCert>,
    wildcards: HashMap<String, StoredCert>,
    secrets: HashMap<String, Vec<String>>,
}

impl CertStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_allowlist(&mut self, allowed: HashSet<String>) {
        self.allowlist = allowed;
    }

    pub fn allowlist(&self) -> &HashSet<String> {
        &self.allowlist
    }

    pub fn add_cert(
        &mut self,
        secret_key: &str,
        cert_pem: &[u8],
        key_pem: &[u8],
    ) -> Result<Vec<String>, Box<dyn Error + Send + Sync>> {
        let cert_chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("failed to parse cert chain: {e}"))?;

        if cert_chain.is_empty() {
            return Err("empty certificate chain".into());
        }

        let (dns_names, not_before) = parse_cert_metadata(cert_chain[0].as_ref())?;
        if dns_names.is_empty() {
            warn!(
                secret = secret_key,
                "no DNS names or SANs found in certificate"
            );
            return Ok(Vec::new());
        }

        let key_der = PrivateKeyDer::from_pem_slice(key_pem)
            .map_err(|e| format!("failed to parse private key: {e}"))?;
        let signing_key = rustls::crypto::ring::sign::any_supported_type(&key_der)
            .map_err(|e| format!("unsupported private key: {e}"))?;

        let certified_key = Arc::new(CertifiedKey::new(cert_chain, signing_key));

        // Remove old associations for this secret if any
        self.remove_cert(secret_key);

        let mut registered = Vec::new();
        for name in &dns_names {
            let normalized = normalize_name(name);
            let is_wildcard = normalized.starts_with("*.");
            let lookup_key = if is_wildcard {
                normalized.strip_prefix("*.").unwrap().to_string()
            } else {
                normalized.clone()
            };

            let map = if is_wildcard {
                &mut self.wildcards
            } else {
                &mut self.exact
            };

            let should_insert = match map.get(&lookup_key) {
                Some(existing) => {
                    if not_before > existing.not_before {
                        warn!(
                            domain = %normalized,
                            secret = %secret_key,
                            existing_secret = %existing.secret_key,
                            "duplicate SAN: replacing older certificate (notBefore: {}) with newer (notBefore: {})",
                            existing.not_before, not_before
                        );
                        true
                    } else if not_before < existing.not_before {
                        warn!(
                            domain = %normalized,
                            secret = %secret_key,
                            existing_secret = %existing.secret_key,
                            "duplicate SAN: rejecting certificate with older notBefore ({} < {})",
                            not_before, existing.not_before
                        );
                        false
                    } else if existing.secret_key == secret_key {
                        true
                    } else {
                        warn!(
                            domain = %normalized,
                            secret = %secret_key,
                            existing_secret = %existing.secret_key,
                            "duplicate SAN with identical notBefore; rejecting ambiguity"
                        );
                        false
                    }
                }
                None => true,
            };

            if should_insert {
                map.insert(
                    lookup_key,
                    StoredCert {
                        certified_key: certified_key.clone(),
                        not_before,
                        secret_key: secret_key.to_string(),
                    },
                );
                registered.push(normalized);
            }
        }

        self.secrets
            .insert(secret_key.to_string(), registered.clone());
        info!(
            secret = secret_key,
            domains = ?registered,
            not_before,
            "loaded TLS certificate"
        );

        Ok(registered)
    }

    pub fn remove_cert(&mut self, secret_key: &str) {
        if let Some(names) = self.secrets.remove(secret_key) {
            for name in names {
                if let Some(suffix) = name.strip_prefix("*.") {
                    if let Some(entry) = self.wildcards.get(suffix)
                        && entry.secret_key == secret_key
                    {
                        self.wildcards.remove(suffix);
                    }
                } else if let Some(entry) = self.exact.get(&name)
                    && entry.secret_key == secret_key
                {
                    self.exact.remove(&name);
                }
            }
            debug!(secret = secret_key, "removed TLS certificate");
        }
    }

    pub fn resolve(&self, host: &str) -> Option<Arc<CertifiedKey>> {
        let normalized = normalize_name(host);

        // 1. Check exact match
        if let Some(entry) = self.exact.get(&normalized) {
            return Some(entry.certified_key.clone());
        }

        // 2. Check single-level wildcard match
        if let Some((_prefix, suffix)) = normalized.split_once('.')
            && let Some(entry) = self.wildcards.get(suffix)
        {
            return Some(entry.certified_key.clone());
        }

        None
    }
}

pub struct DynamicCertResolver {
    cert_store: Arc<std::sync::RwLock<CertStore>>,
    allowlist: Allowlist,
}

impl std::fmt::Debug for DynamicCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynamicCertResolver").finish()
    }
}

impl DynamicCertResolver {
    pub fn new(cert_store: Arc<std::sync::RwLock<CertStore>>, allowlist: Allowlist) -> Self {
        Self {
            cert_store,
            allowlist,
        }
    }
}

impl ResolvesServerCert for DynamicCertResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        let sni = client_hello.server_name()?;
        let normalized = normalize_name(sni);

        // First check allowlist: reject immediately if not in allowlist
        if let Ok(allowed) = self.allowlist.try_read()
            && !allowed.contains(&normalized)
        {
            debug!(sni = %normalized, "sni not in allowlist, rejecting handshake");
            return None;
        }

        let store = self.cert_store.read().ok()?;
        if !store.allowlist.contains(&normalized) {
            debug!(sni = %normalized, "sni not in cert store allowlist, rejecting handshake");
            return None;
        }

        let cert = store.resolve(&normalized);
        if cert.is_none() {
            warn!(sni = %normalized, "no matching certificate found for allowed host");
        }
        cert
    }
}

pub fn normalize_name(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Extract all DNS names (SANs and subject CN as fallback) along with notBefore from a DER-encoded X.509 certificate.
pub fn parse_cert_metadata(
    der: &[u8],
) -> Result<(HashSet<String>, i64), Box<dyn Error + Send + Sync>> {
    let (_, cert) = x509_parser::parse_x509_certificate(der)
        .map_err(|e| format!("failed to parse X.509 certificate: {e}"))?;
    let not_before = cert.validity().not_before.timestamp();

    let mut names = HashSet::new();
    if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
        for name in &san_ext.value.general_names {
            if let GeneralName::DNSName(dns) = name {
                names.insert(normalize_name(dns));
            }
        }
    }

    // Ignore CN when SANs are present; use subject CN only as fallback if no SANs exist
    if names.is_empty() {
        for cn in cert.subject().iter_common_name() {
            if let Ok(s) = cn.as_str() {
                names.insert(normalize_name(s));
            }
        }
    }

    Ok((names, not_before))
}

/// Convenience function extracting only DNS names.
pub fn extract_dns_names(der: &[u8]) -> HashSet<String> {
    parse_cert_metadata(der)
        .map(|(names, _)| names)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_dns_names_rcgen() {
        let mut params = rcgen::CertificateParams::default();
        params.subject_alt_names = vec![
            rcgen::SanType::DnsName(rcgen::Ia5String::try_from("hello.example.com").unwrap()),
            rcgen::SanType::DnsName(rcgen::Ia5String::try_from("*.wildcard.example.com").unwrap()),
        ];
        // Set a CN to verify it is ignored when SANs are present
        params.distinguished_name.push(
            rcgen::DnType::CommonName,
            rcgen::DnValue::Utf8String("ignored-cn.example.com".to_string()),
        );

        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let cert = params.self_signed(&key).unwrap();
        let der = cert.der();

        let (names, _not_before) = parse_cert_metadata(der).unwrap();
        assert!(names.contains("hello.example.com"));
        assert!(names.contains("*.wildcard.example.com"));
        assert!(
            !names.contains("ignored-cn.example.com"),
            "CN must be ignored when SANs are present"
        );
    }

    #[test]
    fn test_cn_fallback_when_no_san() {
        let mut params = rcgen::CertificateParams::default();
        params.distinguished_name.push(
            rcgen::DnType::CommonName,
            rcgen::DnValue::Utf8String("fallback-cn.example.com".to_string()),
        );
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let cert = params.self_signed(&key).unwrap();
        let der = cert.der();

        let (names, _) = parse_cert_metadata(der).unwrap();
        assert!(names.contains("fallback-cn.example.com"));
    }

    #[test]
    fn test_duplicate_san_prefers_newest_not_before() {
        let mut store = CertStore::new();

        // Older cert: 2024-01-01
        let mut p1 = rcgen::CertificateParams::default();
        p1.not_before = rcgen::date_time_ymd(2024, 1, 1);
        p1.subject_alt_names = vec![rcgen::SanType::DnsName(
            rcgen::Ia5String::try_from("shared.example.com").unwrap(),
        )];
        let k1 = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let c1 = p1.self_signed(&k1).unwrap();

        // Newer cert: 2025-01-01
        let mut p2 = rcgen::CertificateParams::default();
        p2.not_before = rcgen::date_time_ymd(2025, 1, 1);
        p2.subject_alt_names = vec![rcgen::SanType::DnsName(
            rcgen::Ia5String::try_from("shared.example.com").unwrap(),
        )];
        let k2 = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let c2 = p2.self_signed(&k2).unwrap();

        // Add older cert first
        store
            .add_cert(
                "gate/cert-old",
                c1.pem().as_bytes(),
                k1.serialize_pem().as_bytes(),
            )
            .unwrap();
        assert_eq!(
            store.exact.get("shared.example.com").unwrap().secret_key,
            "gate/cert-old"
        );

        // Add newer cert -> replaces older cert
        store
            .add_cert(
                "gate/cert-new",
                c2.pem().as_bytes(),
                k2.serialize_pem().as_bytes(),
            )
            .unwrap();
        assert_eq!(
            store.exact.get("shared.example.com").unwrap().secret_key,
            "gate/cert-new"
        );

        // Re-adding older cert -> rejected, newer cert remains!
        store
            .add_cert(
                "gate/cert-old",
                c1.pem().as_bytes(),
                k1.serialize_pem().as_bytes(),
            )
            .unwrap();
        assert_eq!(
            store.exact.get("shared.example.com").unwrap().secret_key,
            "gate/cert-new"
        );
    }

    #[test]
    fn test_cert_store_exact_and_wildcard() {
        let mut store = CertStore::new();

        let mut p1 = rcgen::CertificateParams::default();
        p1.subject_alt_names = vec![rcgen::SanType::DnsName(
            rcgen::Ia5String::try_from("varden.flaatten.org").unwrap(),
        )];
        let k1 = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let c1 = p1.self_signed(&k1).unwrap();

        let mut p2 = rcgen::CertificateParams::default();
        p2.subject_alt_names = vec![rcgen::SanType::DnsName(
            rcgen::Ia5String::try_from("*.hello.fn.flaatten.org").unwrap(),
        )];
        let k2 = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let c2 = p2.self_signed(&k2).unwrap();

        store
            .add_cert(
                "varden-blog/varden.flaatten.org",
                c1.pem().as_bytes(),
                k1.serialize_pem().as_bytes(),
            )
            .unwrap();

        store
            .add_cert(
                "hello/hello.fn.flaatten.org",
                c2.pem().as_bytes(),
                k2.serialize_pem().as_bytes(),
            )
            .unwrap();

        // Exact match
        assert!(store.resolve("varden.flaatten.org").is_some());
        assert!(store.resolve("VARDEN.FLAATTEN.ORG.").is_some());

        // Wildcard match
        assert!(store.resolve("hello.hello.fn.flaatten.org").is_some());
        assert!(store.resolve("api.hello.fn.flaatten.org").is_some());

        // Multi-level should not match single wildcard
        assert!(store.resolve("sub.app.hello.fn.flaatten.org").is_none());

        // Non-matching
        assert!(store.resolve("other.example.com").is_none());

        // Deletion
        store.remove_cert("hello/hello.fn.flaatten.org");
        assert!(store.resolve("hello.hello.fn.flaatten.org").is_none());
        assert!(store.resolve("varden.flaatten.org").is_some());
    }
}
