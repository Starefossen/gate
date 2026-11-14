use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use futures::{StreamExt, TryStreamExt};
use kube::api::{Api, ApiResource, DynamicObject, GroupVersionKind};
use kube::runtime::{WatchStreamExt, watcher};
use tracing::{info, warn};

use crate::Allowlist;
use crate::cert::CertStore;

const ANNOTATION_KEY: &str = "gate.flaatten.org/expose";

/// Watch health, tracked per watcher (services, domain mappings, secrets).
/// When any one of them has been failing (or not yet connected) for too long,
/// the allowlist or cert store may be stale and gate stops reporting ready.
/// One watcher's events never clear another's failure.
pub struct SyncStatus {
    failing_since: std::sync::Mutex<[Option<std::time::Instant>; WATCHERS]>,
}

const WATCHERS: usize = 3;
const SERVICES: usize = 0;
const MAPPINGS: usize = 1;
const SECRETS: usize = 2;

impl Default for SyncStatus {
    fn default() -> Self {
        Self {
            failing_since: std::sync::Mutex::new([Some(std::time::Instant::now()); WATCHERS]),
        }
    }
}

impl SyncStatus {
    pub fn ok(&self, watcher: usize) {
        self.failing_since.lock().unwrap()[watcher] = None;
    }

    pub fn err(&self, watcher: usize) {
        self.failing_since.lock().unwrap()[watcher].get_or_insert_with(std::time::Instant::now);
    }

    pub fn is_stale(&self, max: std::time::Duration) -> bool {
        self.failing_since
            .lock()
            .unwrap()
            .iter()
            .any(|t| t.is_some_and(|t| t.elapsed() > max))
    }
}

/// Check whether a Knative Service has the expose annotation set to "true".
fn is_exposed(svc: &DynamicObject) -> bool {
    svc.metadata
        .annotations
        .as_ref()
        .and_then(|a| a.get(ANNOTATION_KEY))
        .map(|v| v == "true")
        .unwrap_or(false)
}

/// Extract the hostname from a Knative Service's `.status.url` field.
/// Strips the scheme prefix and trailing slash.
fn extract_hostname(svc: &DynamicObject) -> Option<String> {
    svc.data
        .get("status")
        .and_then(|s| s.get("url"))
        .and_then(|u| u.as_str())
        .and_then(|u| {
            u.strip_prefix("https://")
                .or_else(|| u.strip_prefix("http://"))
                .map(|h| h.trim_end_matches('/').to_string())
        })
}

/// Exposed services keyed by namespace/name. The allowlist is derived from
/// the values, so a delete or de-annotation drops the host immediately.
#[derive(Default)]
struct State {
    hosts: HashMap<String, String>,
    pending: Option<HashMap<String, String>>,
}

fn key(svc: &DynamicObject) -> String {
    format!(
        "{}/{}",
        svc.metadata.namespace.as_deref().unwrap_or(""),
        svc.metadata.name.as_deref().unwrap_or("")
    )
}

fn exposed_host(svc: &DynamicObject) -> Option<String> {
    if !is_exposed(svc) {
        return None;
    }
    let host = extract_hostname(svc);
    if host.is_none() {
        warn!(
            service = key(svc),
            "service has expose annotation but no status URL yet"
        );
    }
    host
}

impl State {
    /// Applies a watch event; returns true if the host set may have changed.
    fn apply(&mut self, event: watcher::Event<DynamicObject>) -> bool {
        match event {
            watcher::Event::Apply(svc) => {
                let k = key(&svc);
                match exposed_host(&svc) {
                    Some(h) => self.hosts.insert(k, h.clone()) != Some(h),
                    None => self.hosts.remove(&k).is_some(),
                }
            }
            watcher::Event::Delete(svc) => self.hosts.remove(&key(&svc)).is_some(),
            watcher::Event::Init => {
                self.pending = Some(HashMap::new());
                false
            }
            watcher::Event::InitApply(svc) => {
                if let (Some(p), Some(h)) = (self.pending.as_mut(), exposed_host(&svc)) {
                    p.insert(key(&svc), h);
                }
                false
            }
            watcher::Event::InitDone => match self.pending.take() {
                Some(p) => {
                    self.hosts = p;
                    true
                }
                None => false,
            },
        }
    }

    fn host_set(&self) -> HashSet<String> {
        self.hosts.values().cloned().collect()
    }
}

#[derive(Default)]
struct SecretState {
    pending: Option<Vec<k8s_openapi::api::core::v1::Secret>>,
    initialized: bool,
}

fn check_coverage(store: &CertStore) -> Vec<String> {
    let mut missing = Vec::new();
    for host in store.allowlist() {
        if store.resolve(host).is_none() {
            warn!(
                host = %host,
                "allowlisted host has no matching TLS certificate in gate namespace"
            );
            missing.push(host.clone());
        }
    }
    missing
}

impl SecretState {
    fn apply(
        &mut self,
        cert_store: &Arc<std::sync::RwLock<CertStore>>,
        event: watcher::Event<k8s_openapi::api::core::v1::Secret>,
    ) -> Option<Vec<String>> {
        match event {
            watcher::Event::Apply(secret) => {
                if let Ok(mut store) = cert_store.write() {
                    apply_secret(&mut store, &secret);
                    if self.initialized {
                        return Some(check_coverage(&store));
                    }
                }
                None
            }
            watcher::Event::Delete(secret) => {
                let key = format!(
                    "{}/{}",
                    secret.metadata.namespace.as_deref().unwrap_or(""),
                    secret.metadata.name.as_deref().unwrap_or("")
                );
                if let Ok(mut store) = cert_store.write() {
                    store.remove_cert(&key);
                    if self.initialized {
                        return Some(check_coverage(&store));
                    }
                }
                None
            }
            watcher::Event::Init => {
                self.pending = Some(Vec::new());
                None
            }
            watcher::Event::InitApply(secret) => {
                if let Some(p) = self.pending.as_mut() {
                    p.push(secret);
                }
                None
            }
            watcher::Event::InitDone => {
                if let Some(secrets) = self.pending.take()
                    && let Ok(mut store) = cert_store.write()
                {
                    let mut new_store = CertStore::new();
                    new_store.set_allowlist(store.allowlist().clone());
                    for s in &secrets {
                        apply_secret(&mut new_store, s);
                    }
                    self.initialized = true;
                    let missing = check_coverage(&new_store);
                    *store = new_store;
                    Some(missing)
                } else {
                    None
                }
            }
        }
    }
}

enum ControllerEvent {
    Service(watcher::Event<DynamicObject>),
    DomainMapping(watcher::Event<DynamicObject>),
    Secret(watcher::Event<k8s_openapi::api::core::v1::Secret>),
}

impl ControllerEvent {
    fn watcher(&self) -> usize {
        match self {
            Self::Service(_) => SERVICES,
            Self::DomainMapping(_) => MAPPINGS,
            Self::Secret(_) => SECRETS,
        }
    }
}

fn watch_custom(
    client: kube::Client,
    group: &str,
    version: &str,
    kind: &str,
) -> impl futures::Stream<Item = Result<watcher::Event<DynamicObject>, watcher::Error>> {
    let gvk = GroupVersionKind::gvk(group, version, kind);
    let api: Api<DynamicObject> = Api::all_with(client, &ApiResource::from_gvk(&gvk));
    watcher(api, watcher::Config::default()).default_backoff()
}

pub fn apply_secret(store: &mut CertStore, secret: &k8s_openapi::api::core::v1::Secret) {
    let is_tls = secret.type_.as_deref() == Some("kubernetes.io/tls")
        || secret
            .data
            .as_ref()
            .map(|d| d.contains_key("tls.crt") && d.contains_key("tls.key"))
            .unwrap_or(false);
    if !is_tls {
        return;
    }

    let Some(data) = secret.data.as_ref() else {
        return;
    };
    let Some(cert_bytes) = data.get("tls.crt").map(|bs| &bs.0) else {
        return;
    };
    let Some(key_bytes) = data.get("tls.key").map(|bs| &bs.0) else {
        return;
    };

    let key = format!(
        "{}/{}",
        secret.metadata.namespace.as_deref().unwrap_or(""),
        secret.metadata.name.as_deref().unwrap_or("")
    );

    if let Err(e) = store.add_cert(&key, cert_bytes, key_bytes) {
        warn!(secret = %key, error = %e, "failed to load TLS certificate from secret");
    }
}

async fn update_allowlist(
    states: &[State; 2],
    allowlist: &Allowlist,
    cert_store: &Arc<std::sync::RwLock<CertStore>>,
    secrets_initialized: bool,
) -> Option<Vec<String>> {
    let hosts: HashSet<String> = states.iter().flat_map(State::host_set).collect();
    {
        let mut guard = allowlist.write().await;
        if *guard != hosts {
            *guard = hosts.clone();
            info!(count = guard.len(), hosts = ?*guard, "allowlist updated");
        }
    }
    if let Ok(mut store) = cert_store.write() {
        store.set_allowlist(hosts.clone());
        if secrets_initialized {
            return Some(check_coverage(&store));
        }
    }
    None
}

/// Watches Knative Services, DomainMappings, and namespaced TLS Secrets in gate namespace.
/// Updates allowlist on exposed route changes and loads/reloads certificates.
pub async fn run(
    allowlist: Allowlist,
    cert_store: Arc<std::sync::RwLock<CertStore>>,
    sync: Arc<SyncStatus>,
) -> Result<(), Box<dyn std::error::Error>> {
    let client = kube::Client::try_default().await?;
    let gate_ns = std::env::var("GATE_NAMESPACE").unwrap_or_else(|_| "gate".to_string());

    info!(
        gate_namespace = %gate_ns,
        "watching Knative Services, DomainMappings, and namespaced TLS Secrets"
    );

    let services = watch_custom(client.clone(), "serving.knative.dev", "v1", "Service")
        .map_ok(ControllerEvent::Service)
        .map_err(|e| (SERVICES, e));
    let mappings = watch_custom(
        client.clone(),
        "serving.knative.dev",
        "v1beta1",
        "DomainMapping",
    )
    .map_ok(ControllerEvent::DomainMapping)
    .map_err(|e| (MAPPINGS, e));

    let secrets_api: Api<k8s_openapi::api::core::v1::Secret> =
        Api::namespaced(client.clone(), &gate_ns);
    let secrets_config = watcher::Config::default().fields("type=kubernetes.io/tls");
    let secrets = watcher(secrets_api, secrets_config)
        .default_backoff()
        .map_ok(ControllerEvent::Secret)
        .map_err(|e| (SECRETS, e));

    let stream = futures::stream::select(futures::stream::select(services, mappings), secrets);
    tokio::pin!(stream);

    let mut states = [State::default(), State::default()];
    let mut secret_state = SecretState::default();

    while let Some(item) = stream.next().await {
        let event = match item {
            Ok(e) => {
                sync.ok(e.watcher());
                e
            }
            Err((watcher, err)) => {
                sync.err(watcher);
                warn!(watcher, error = %err, "watcher error, continuing with backoff");
                continue;
            }
        };

        match event {
            ControllerEvent::Service(e) => {
                if states[0].apply(e) {
                    update_allowlist(&states, &allowlist, &cert_store, secret_state.initialized)
                        .await;
                }
            }
            ControllerEvent::DomainMapping(e) => {
                if states[1].apply(e) {
                    update_allowlist(&states, &allowlist, &cert_store, secret_state.initialized)
                        .await;
                }
            }
            ControllerEvent::Secret(e) => {
                secret_state.apply(&cert_store, e);
            }
        }
    }

    warn!("watcher stream ended unexpectedly");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use kube::api::ObjectMeta;

    use super::*;

    #[test]
    fn sync_status_goes_stale_and_recovers() {
        use std::time::Duration;
        let all_ok = |s: &SyncStatus| (0..WATCHERS).for_each(|w| s.ok(w));

        let s = SyncStatus::default();
        assert!(!s.is_stale(Duration::from_secs(60)));
        std::thread::sleep(Duration::from_millis(5));
        assert!(s.is_stale(Duration::from_millis(1)));
        all_ok(&s);
        assert!(!s.is_stale(Duration::ZERO));
        s.err(SERVICES);
        std::thread::sleep(Duration::from_millis(5));
        assert!(s.is_stale(Duration::from_millis(1)));
        assert!(!s.is_stale(Duration::from_secs(60)));
        s.ok(SERVICES);
        assert!(!s.is_stale(Duration::from_millis(1)));
    }

    #[test]
    fn sync_status_is_not_ready_until_every_watcher_connects() {
        let s = SyncStatus::default();
        s.ok(SERVICES);
        s.ok(SECRETS);
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert!(s.is_stale(std::time::Duration::from_millis(1)));
        s.ok(MAPPINGS);
        assert!(!s.is_stale(std::time::Duration::ZERO));
    }

    #[test]
    fn sync_status_dead_watcher_is_not_hidden_by_others() {
        let s = SyncStatus::default();
        (0..WATCHERS).for_each(|w| s.ok(w));
        s.err(MAPPINGS);
        std::thread::sleep(std::time::Duration::from_millis(5));
        s.ok(SERVICES);
        s.ok(SECRETS);
        assert!(s.is_stale(std::time::Duration::from_millis(1)));
        s.err(MAPPINGS);
        assert!(s.is_stale(std::time::Duration::from_millis(1)));
        s.ok(MAPPINGS);
        assert!(!s.is_stale(std::time::Duration::ZERO));
    }

    fn make_service(
        name: &str,
        ns: &str,
        annotations: Option<BTreeMap<String, String>>,
        status_url: Option<&str>,
    ) -> DynamicObject {
        let mut data = serde_json::Map::new();
        if let Some(url) = status_url {
            let mut status = serde_json::Map::new();
            status.insert("url".into(), serde_json::Value::String(url.into()));
            data.insert("status".into(), serde_json::Value::Object(status));
        }

        DynamicObject {
            metadata: ObjectMeta {
                name: Some(name.into()),
                namespace: Some(ns.into()),
                annotations,
                ..Default::default()
            },
            types: None,
            data: serde_json::Value::Object(data),
        }
    }

    fn expose_annotation() -> Option<BTreeMap<String, String>> {
        let mut m = BTreeMap::new();
        m.insert(ANNOTATION_KEY.into(), "true".into());
        Some(m)
    }

    #[test]
    fn test_is_exposed_true() {
        let svc = make_service("hello", "default", expose_annotation(), None);
        assert!(is_exposed(&svc));
    }

    #[test]
    fn test_is_exposed_false_no_annotation() {
        let svc = make_service("hello", "default", None, None);
        assert!(!is_exposed(&svc));
    }

    #[test]
    fn test_is_exposed_false_wrong_value() {
        let mut m = BTreeMap::new();
        m.insert(ANNOTATION_KEY.into(), "false".into());
        let svc = make_service("hello", "default", Some(m), None);
        assert!(!is_exposed(&svc));
    }

    #[test]
    fn test_is_exposed_false_empty_value() {
        let mut m = BTreeMap::new();
        m.insert(ANNOTATION_KEY.into(), "".into());
        let svc = make_service("hello", "default", Some(m), None);
        assert!(!is_exposed(&svc));
    }

    #[test]
    fn test_extract_hostname_https() {
        let svc = make_service(
            "hello",
            "ns",
            None,
            Some("https://hello.ns.fn.flaatten.org"),
        );
        assert_eq!(
            extract_hostname(&svc),
            Some("hello.ns.fn.flaatten.org".into())
        );
    }

    #[test]
    fn test_extract_hostname_http() {
        let svc = make_service("hello", "ns", None, Some("http://hello.ns.fn.flaatten.org"));
        assert_eq!(
            extract_hostname(&svc),
            Some("hello.ns.fn.flaatten.org".into())
        );
    }

    #[test]
    fn test_extract_hostname_trailing_slash() {
        let svc = make_service(
            "hello",
            "ns",
            None,
            Some("https://hello.ns.fn.flaatten.org/"),
        );
        assert_eq!(
            extract_hostname(&svc),
            Some("hello.ns.fn.flaatten.org".into())
        );
    }

    #[test]
    fn test_extract_hostname_no_status() {
        let svc = make_service("hello", "ns", None, None);
        assert_eq!(extract_hostname(&svc), None);
    }

    #[test]
    fn test_extract_hostname_no_scheme() {
        let svc = make_service("hello", "ns", None, Some("hello.ns.fn.flaatten.org"));
        assert_eq!(extract_hostname(&svc), None);
    }

    const URL: &str = "https://hello.ns.fn.flaatten.org";
    const HOST: &str = "hello.ns.fn.flaatten.org";

    fn exposed() -> DynamicObject {
        make_service("hello", "ns", expose_annotation(), Some(URL))
    }

    #[test]
    fn apply_adds_and_deannotation_removes() {
        let mut st = State::default();
        assert!(st.apply(watcher::Event::Apply(exposed())));
        assert!(st.host_set().contains(HOST));
        assert!(!st.apply(watcher::Event::Apply(exposed())));
        assert!(st.apply(watcher::Event::Apply(make_service(
            "hello",
            "ns",
            None,
            Some(URL)
        ))));
        assert!(st.host_set().is_empty());
    }

    #[test]
    fn delete_removes() {
        let mut st = State::default();
        st.apply(watcher::Event::Apply(exposed()));
        assert!(st.apply(watcher::Event::Delete(exposed())));
        assert!(st.host_set().is_empty());
    }

    #[test]
    fn relist_drops_services_deleted_while_disconnected() {
        let mut st = State::default();
        st.apply(watcher::Event::Apply(exposed()));
        st.apply(watcher::Event::Init);
        st.apply(watcher::Event::InitApply(make_service(
            "other",
            "ns",
            expose_annotation(),
            Some("https://other.ns.fn.flaatten.org"),
        )));
        assert!(st.host_set().contains(HOST), "old set kept until InitDone");
        assert!(st.apply(watcher::Event::InitDone));
        let hosts = st.host_set();
        assert_eq!(hosts.len(), 1);
        assert!(hosts.contains("other.ns.fn.flaatten.org"));
    }

    #[test]
    fn exposed_without_url_is_not_added() {
        let mut st = State::default();
        st.apply(watcher::Event::Apply(make_service(
            "hello",
            "ns",
            expose_annotation(),
            None,
        )));
        assert!(st.host_set().is_empty());
    }

    #[test]
    fn shared_host_survives_one_removal() {
        let mut st = State::default();
        st.apply(watcher::Event::Apply(exposed()));
        st.apply(watcher::Event::Apply(make_service(
            "dup",
            "ns",
            expose_annotation(),
            Some(URL),
        )));
        st.apply(watcher::Event::Delete(exposed()));
        assert!(st.host_set().contains(HOST));
    }

    #[test]
    fn same_key_in_separate_states_does_not_collide() {
        let mut services = State::default();
        let mut mappings = State::default();
        services.apply(watcher::Event::Apply(exposed()));
        mappings.apply(watcher::Event::Apply(make_service(
            "hello",
            "ns",
            expose_annotation(),
            Some("https://blog.example.org"),
        )));
        let union = |a: &State, b: &State| -> HashSet<String> {
            [a, b].into_iter().flat_map(State::host_set).collect()
        };
        assert_eq!(union(&services, &mappings).len(), 2);
        mappings.apply(watcher::Event::Delete(exposed()));
        assert_eq!(
            union(&services, &mappings),
            HashSet::from([HOST.to_string()])
        );
    }

    #[test]
    fn test_apply_and_remove_secret() {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut params = rcgen::CertificateParams::default();
        params.subject_alt_names = vec![rcgen::SanType::DnsName(
            rcgen::Ia5String::try_from("hello.fn.flaatten.org").unwrap(),
        )];
        let cert = params.self_signed(&key).unwrap();

        let mut data = BTreeMap::new();
        data.insert(
            "tls.crt".into(),
            k8s_openapi::ByteString(cert.pem().into_bytes()),
        );
        data.insert(
            "tls.key".into(),
            k8s_openapi::ByteString(key.serialize_pem().into_bytes()),
        );

        let secret = k8s_openapi::api::core::v1::Secret {
            metadata: ObjectMeta {
                name: Some("hello.fn.flaatten.org".into()),
                namespace: Some("hello".into()),
                ..Default::default()
            },
            type_: Some("kubernetes.io/tls".into()),
            data: Some(data),
            ..Default::default()
        };

        let mut store = CertStore::new();
        apply_secret(&mut store, &secret);
        assert!(store.resolve("hello.fn.flaatten.org").is_some());

        store.remove_cert("hello/hello.fn.flaatten.org");
        assert!(store.resolve("hello.fn.flaatten.org").is_none());
    }

    #[test]
    fn test_apply_secret_ignores_non_tls() {
        let mut data = BTreeMap::new();
        data.insert(
            "password".into(),
            k8s_openapi::ByteString(b"secret".to_vec()),
        );

        let secret = k8s_openapi::api::core::v1::Secret {
            metadata: ObjectMeta {
                name: Some("db-creds".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            type_: Some("Opaque".into()),
            data: Some(data),
            ..Default::default()
        };

        let mut store = CertStore::new();
        apply_secret(&mut store, &secret);
        assert!(store.resolve("hello.fn.flaatten.org").is_none());
    }

    fn make_tls_secret(
        name: &str,
        namespace: &str,
        dns_name: &str,
    ) -> k8s_openapi::api::core::v1::Secret {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut params = rcgen::CertificateParams::default();
        params.subject_alt_names = vec![rcgen::SanType::DnsName(
            rcgen::Ia5String::try_from(dns_name).unwrap(),
        )];
        let cert = params.self_signed(&key).unwrap();

        let mut data = BTreeMap::new();
        data.insert(
            "tls.crt".into(),
            k8s_openapi::ByteString(cert.pem().into_bytes()),
        );
        data.insert(
            "tls.key".into(),
            k8s_openapi::ByteString(key.serialize_pem().into_bytes()),
        );

        k8s_openapi::api::core::v1::Secret {
            metadata: ObjectMeta {
                name: Some(name.into()),
                namespace: Some(namespace.into()),
                ..Default::default()
            },
            type_: Some("kubernetes.io/tls".into()),
            data: Some(data),
            ..Default::default()
        }
    }

    #[test]
    fn test_secret_relist_drops_secrets_deleted_while_disconnected() {
        let secret_a = make_tls_secret("cert-a", "gate", "a.fn.flaatten.org");
        let secret_b = make_tls_secret("cert-b", "gate", "b.fn.flaatten.org");

        let cert_store = Arc::new(std::sync::RwLock::new(CertStore::new()));
        let mut state = SecretState::default();

        state.apply(&cert_store, watcher::Event::Apply(secret_a));
        assert!(
            cert_store
                .read()
                .unwrap()
                .resolve("a.fn.flaatten.org")
                .is_some()
        );

        // Watch gap begins: Init
        state.apply(&cert_store, watcher::Event::Init);
        state.apply(&cert_store, watcher::Event::InitApply(secret_b));

        // Prior state preserved until InitDone
        assert!(
            cert_store
                .read()
                .unwrap()
                .resolve("a.fn.flaatten.org")
                .is_some()
        );
        assert!(
            cert_store
                .read()
                .unwrap()
                .resolve("b.fn.flaatten.org")
                .is_none()
        );

        // Watch gap ends: InitDone
        state.apply(&cert_store, watcher::Event::InitDone);

        // a was deleted during gap, b is now present
        assert!(
            cert_store
                .read()
                .unwrap()
                .resolve("a.fn.flaatten.org")
                .is_none()
        );
        assert!(
            cert_store
                .read()
                .unwrap()
                .resolve("b.fn.flaatten.org")
                .is_some()
        );
    }

    #[tokio::test]
    async fn test_spurious_missing_cert_warning_suppressed_until_init_done() {
        let cert_store = Arc::new(std::sync::RwLock::new(CertStore::new()));
        let allowlist: Allowlist = Arc::new(tokio::sync::RwLock::new(HashSet::new()));
        let mut states = [State::default(), State::default()];
        let mut secret_state = SecretState::default();

        // 1. Service discovered at startup before secret watch finishes initial sync
        assert!(states[0].apply(watcher::Event::Apply(exposed())));
        assert!(!secret_state.initialized);

        // Allowlist update before InitDone must NOT check coverage
        let missing =
            update_allowlist(&states, &allowlist, &cert_store, secret_state.initialized).await;
        assert_eq!(
            missing, None,
            "coverage must not be checked before secret watch reaches InitDone"
        );
        assert!(allowlist.read().await.contains(HOST));

        // 2. Secret watch streams initial list
        let secret = make_tls_secret("cert-hello", "gate", HOST);
        secret_state.apply(&cert_store, watcher::Event::Init);
        secret_state.apply(&cert_store, watcher::Event::InitApply(secret));

        // 3. Secret watch completes initial list: InitDone
        let missing = secret_state.apply(&cert_store, watcher::Event::InitDone);
        assert!(secret_state.initialized);
        assert_eq!(
            missing,
            Some(vec![]),
            "InitDone must check coverage, finding cert matches host"
        );

        // 4. Later allowlist change after InitDone checks coverage
        states[1].apply(watcher::Event::Apply(make_service(
            "uncovered",
            "ns",
            expose_annotation(),
            Some("https://uncovered.fn.flaatten.org"),
        )));
        let missing =
            update_allowlist(&states, &allowlist, &cert_store, secret_state.initialized).await;
        assert_eq!(
            missing,
            Some(vec!["uncovered.fn.flaatten.org".to_string()]),
            "later allowlist change must check coverage"
        );

        // 5. Later secret change (delete) after InitDone checks coverage
        let secret = make_tls_secret("cert-hello", "gate", HOST);
        let missing = secret_state.apply(&cert_store, watcher::Event::Delete(secret));
        assert!(
            missing
                .as_ref()
                .map(|m| m.contains(&HOST.to_string()))
                .unwrap_or(false),
            "later secret change must check coverage"
        );
    }
}
