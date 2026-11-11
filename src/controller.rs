use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use futures::TryStreamExt;
use kube::api::{Api, ApiResource, DynamicObject, GroupVersionKind};
use kube::runtime::{WatchStreamExt, watcher};
use tracing::{info, warn};

use crate::Allowlist;
use crate::cert::CertStore;

const ANNOTATION_KEY: &str = "gate.flaatten.org/expose";

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

enum ControllerEvent {
    Service(watcher::Event<DynamicObject>),
    DomainMapping(watcher::Event<DynamicObject>),
    Secret(watcher::Event<k8s_openapi::api::core::v1::Secret>),
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
) {
    let hosts: HashSet<String> = states.iter().flat_map(State::host_set).collect();
    {
        let mut guard = allowlist.write().await;
        if *guard != hosts {
            *guard = hosts.clone();
            info!(count = guard.len(), hosts = ?*guard, "allowlist updated");
        }
    }
    if let Ok(mut store) = cert_store.write() {
        store.set_allowlist(hosts);
    }
}

/// Watches Knative Services, DomainMappings, and TLS Secrets.
/// Updates allowlist on exposed route changes and loads/reloads certificates.
pub async fn run(
    allowlist: Allowlist,
    cert_store: Arc<std::sync::RwLock<CertStore>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let client = kube::Client::try_default().await?;

    info!("watching Knative Services, DomainMappings, and Secrets for TLS termination");

    let services = watch_custom(client.clone(), "serving.knative.dev", "v1", "Service")
        .map_ok(ControllerEvent::Service);
    let mappings = watch_custom(
        client.clone(),
        "serving.knative.dev",
        "v1beta1",
        "DomainMapping",
    )
    .map_ok(ControllerEvent::DomainMapping);

    let secrets_api: Api<k8s_openapi::api::core::v1::Secret> = Api::all(client);
    let secrets = watcher(secrets_api, watcher::Config::default())
        .default_backoff()
        .map_ok(ControllerEvent::Secret);

    let stream = futures::stream::select(futures::stream::select(services, mappings), secrets);
    tokio::pin!(stream);

    let mut states = [State::default(), State::default()];

    while let Some(event) = stream.try_next().await? {
        match event {
            ControllerEvent::Service(e) => {
                if states[0].apply(e) {
                    update_allowlist(&states, &allowlist, &cert_store).await;
                }
            }
            ControllerEvent::DomainMapping(e) => {
                if states[1].apply(e) {
                    update_allowlist(&states, &allowlist, &cert_store).await;
                }
            }
            ControllerEvent::Secret(e) => match e {
                watcher::Event::Apply(secret) | watcher::Event::InitApply(secret) => {
                    if let Ok(mut store) = cert_store.write() {
                        apply_secret(&mut store, &secret);
                    }
                }
                watcher::Event::Delete(secret) => {
                    let key = format!(
                        "{}/{}",
                        secret.metadata.namespace.as_deref().unwrap_or(""),
                        secret.metadata.name.as_deref().unwrap_or("")
                    );
                    if let Ok(mut store) = cert_store.write() {
                        store.remove_cert(&key);
                    }
                }
                _ => {}
            },
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use kube::api::ObjectMeta;

    use super::*;

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
}
