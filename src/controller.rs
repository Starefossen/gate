use std::collections::HashSet;

use futures::TryStreamExt;
use kube::api::{Api, ApiResource, DynamicObject, GroupVersionKind};
use kube::runtime::{watcher, WatchStreamExt};
use tracing::{debug, info, warn};

use crate::Allowlist;

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

/// Result of processing a Knative Service event.
#[derive(Debug, PartialEq)]
enum Action {
    Add(String),
    Remove(String),
    NoStatusUrl,
    Skip,
}

/// Determine what action to take for a given service event.
fn process_service(svc: &DynamicObject, current_hosts: &HashSet<String>) -> Action {
    let exposed = is_exposed(svc);
    let hostname = extract_hostname(svc);

    match (exposed, hostname) {
        (true, Some(host)) => {
            if !current_hosts.contains(&host) {
                Action::Add(host)
            } else {
                Action::Skip
            }
        }
        (false, Some(host)) => {
            if current_hosts.contains(&host) {
                Action::Remove(host)
            } else {
                Action::Skip
            }
        }
        (true, None) => Action::NoStatusUrl,
        _ => Action::Skip,
    }
}

pub async fn run(allowlist: Allowlist) -> Result<(), Box<dyn std::error::Error>> {
    let client = kube::Client::try_default().await?;

    let gvk = GroupVersionKind::gvk("serving.knative.dev", "v1", "Service");
    let ar = ApiResource::from_gvk(&gvk);
    let api: Api<DynamicObject> = Api::all_with(client, &ar);

    info!("watching Knative Services for gate.flaatten.org/expose annotation");

    let stream = watcher(api, watcher::Config::default())
        .applied_objects()
        .default_backoff();

    tokio::pin!(stream);

    let mut current_hosts: HashSet<String> = HashSet::new();

    while let Some(svc) = stream.try_next().await? {
        let name = svc.metadata.name.as_deref().unwrap_or("unknown");
        let ns = svc.metadata.namespace.as_deref().unwrap_or("default");

        match process_service(&svc, &current_hosts) {
            Action::Add(host) => {
                current_hosts.insert(host.clone());
                info!(service = name, namespace = ns, host, "adding to allowlist");
                rebuild_allowlist(&allowlist, &current_hosts).await;
            }
            Action::Remove(host) => {
                current_hosts.remove(&host);
                info!(service = name, namespace = ns, host, "removing from allowlist");
                rebuild_allowlist(&allowlist, &current_hosts).await;
            }
            Action::NoStatusUrl => {
                warn!(
                    service = name,
                    namespace = ns,
                    "service has expose annotation but no status URL yet"
                );
            }
            Action::Skip => {
                debug!(service = name, namespace = ns, "service not exposed");
            }
        }
    }

    Ok(())
}

async fn rebuild_allowlist(allowlist: &Allowlist, hosts: &HashSet<String>) {
    let mut guard = allowlist.write().await;
    *guard = hosts.clone();
    info!(count = guard.len(), hosts = ?*guard, "allowlist updated");
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
        let svc = make_service("hello", "ns", None, Some("https://hello.ns.fn.flaatten.org"));
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
        let svc = make_service("hello", "ns", None, Some("https://hello.ns.fn.flaatten.org/"));
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

    #[test]
    fn test_process_service_add() {
        let svc = make_service(
            "hello",
            "ns",
            expose_annotation(),
            Some("https://hello.ns.fn.flaatten.org"),
        );
        let hosts = HashSet::new();
        assert_eq!(
            process_service(&svc, &hosts),
            Action::Add("hello.ns.fn.flaatten.org".into())
        );
    }

    #[test]
    fn test_process_service_already_added() {
        let svc = make_service(
            "hello",
            "ns",
            expose_annotation(),
            Some("https://hello.ns.fn.flaatten.org"),
        );
        let mut hosts = HashSet::new();
        hosts.insert("hello.ns.fn.flaatten.org".into());
        assert_eq!(process_service(&svc, &hosts), Action::Skip);
    }

    #[test]
    fn test_process_service_remove() {
        let svc = make_service(
            "hello",
            "ns",
            None,
            Some("https://hello.ns.fn.flaatten.org"),
        );
        let mut hosts = HashSet::new();
        hosts.insert("hello.ns.fn.flaatten.org".into());
        assert_eq!(
            process_service(&svc, &hosts),
            Action::Remove("hello.ns.fn.flaatten.org".into())
        );
    }

    #[test]
    fn test_process_service_not_exposed_not_in_list() {
        let svc = make_service(
            "hello",
            "ns",
            None,
            Some("https://hello.ns.fn.flaatten.org"),
        );
        let hosts = HashSet::new();
        assert_eq!(process_service(&svc, &hosts), Action::Skip);
    }

    #[test]
    fn test_process_service_exposed_no_url() {
        let svc = make_service("hello", "ns", expose_annotation(), None);
        assert_eq!(
            process_service(&svc, &HashSet::new()),
            Action::NoStatusUrl
        );
    }

    #[test]
    fn test_process_service_no_annotation_no_url() {
        let svc = make_service("hello", "ns", None, None);
        assert_eq!(process_service(&svc, &HashSet::new()), Action::Skip);
    }
}
