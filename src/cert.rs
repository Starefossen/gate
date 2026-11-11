use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::sync::Arc;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tracing::{debug, info, warn};

use crate::Allowlist;

/// Stores parsed TLS certificates indexed by exact hostname and wildcard suffix.
#[derive(Default)]
pub struct CertStore {
    allowlist: HashSet<String>,
    exact: HashMap<String, Arc<CertifiedKey>>,
    wildcards: HashMap<String, Arc<CertifiedKey>>,
    secrets: HashMap<String, Vec<String>>,
}

impl CertStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_allowlist(&mut self, allowed: HashSet<String>) {
        self.allowlist = allowed;
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

        let dns_names = extract_dns_names(cert_chain[0].as_ref());
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
            if let Some(suffix) = normalized.strip_prefix("*.") {
                self.wildcards
                    .insert(suffix.to_string(), certified_key.clone());
            } else {
                self.exact.insert(normalized.clone(), certified_key.clone());
            }
            registered.push(normalized);
        }

        self.secrets
            .insert(secret_key.to_string(), registered.clone());
        info!(
            secret = secret_key,
            domains = ?registered,
            "loaded TLS certificate"
        );

        Ok(registered)
    }

    pub fn remove_cert(&mut self, secret_key: &str) {
        if let Some(names) = self.secrets.remove(secret_key) {
            for name in names {
                if let Some(suffix) = name.strip_prefix("*.") {
                    self.wildcards.remove(suffix);
                } else {
                    self.exact.remove(&name);
                }
            }
            debug!(secret = secret_key, "removed TLS certificate");
        }
    }

    pub fn resolve(&self, host: &str) -> Option<Arc<CertifiedKey>> {
        let normalized = normalize_name(host);

        // 1. Check exact match
        if let Some(key) = self.exact.get(&normalized) {
            return Some(key.clone());
        }

        // 2. Check single-level wildcard match
        if let Some((_prefix, suffix)) = normalized.split_once('.')
            && let Some(key) = self.wildcards.get(suffix)
        {
            return Some(key.clone());
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

/// Extract all DNS names (SANs and subject CN) from a DER-encoded X.509 certificate.
pub fn extract_dns_names(der: &[u8]) -> HashSet<String> {
    let mut names = HashSet::new();

    // 1. Extract SANs (Subject Alternative Names) - OID 2.5.29.17: 55 1d 11
    let san_oid = [0x55, 0x1d, 0x11];
    if let Some(pos) = find_subsequence(der, &san_oid) {
        let mut idx = pos + san_oid.len();
        // Skip optional boolean critical (01 01 xx)
        if idx + 3 <= der.len() && der[idx] == 0x01 && der[idx + 1] == 0x01 {
            idx += 3;
        }
        // Next should be OCTET STRING (0x04)
        if idx < der.len()
            && der[idx] == 0x04
            && let Some((octet_data, _)) = read_tlv_value(&der[idx..])
            && !octet_data.is_empty()
            && octet_data[0] == 0x30
            && let Some((seq_data, _)) = read_tlv_value(octet_data)
        {
            let mut p = 0;
            while p < seq_data.len() {
                let tag = seq_data[p];
                if let Some((val, total_len)) = read_tlv_value(&seq_data[p..]) {
                    // Tag [2] context-specific primitive is dNSName
                    if tag == 0x82
                        && let Ok(s) = std::str::from_utf8(val)
                    {
                        names.insert(normalize_name(s));
                    }
                    p += total_len;
                } else {
                    break;
                }
            }
        }
    }

    // 2. Extract Common Name (CN) - OID 2.5.4.3: 55 04 03
    let cn_oid = [0x55, 0x04, 0x03];
    if let Some(pos) = find_subsequence(der, &cn_oid) {
        let idx = pos + cn_oid.len();
        if idx < der.len()
            && let Some((val, _)) = read_tlv_value(&der[idx..])
            && let Ok(s) = std::str::from_utf8(val)
        {
            names.insert(normalize_name(s));
        }
    }

    names
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Reads the value of a TLV element and returns (value_bytes, total_tlv_len)
fn read_tlv_value(data: &[u8]) -> Option<(&[u8], usize)> {
    if data.len() < 2 {
        return None;
    }
    let len_byte = data[1];
    let (val_len, header_len) = if len_byte < 0x80 {
        (len_byte as usize, 2)
    } else {
        let num_len_bytes = (len_byte & 0x7f) as usize;
        if num_len_bytes == 0 || num_len_bytes > 4 || 2 + num_len_bytes > data.len() {
            return None;
        }
        let mut len = 0usize;
        for i in 0..num_len_bytes {
            len = (len << 8) | (data[2 + i] as usize);
        }
        (len, 2 + num_len_bytes)
    };

    if header_len + val_len > data.len() {
        return None;
    }
    Some((
        &data[header_len..header_len + val_len],
        header_len + val_len,
    ))
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
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let cert = params.self_signed(&key).unwrap();
        let der = cert.der();

        let names = extract_dns_names(der);
        assert!(names.contains("hello.example.com"));
        assert!(names.contains("*.wildcard.example.com"));
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
