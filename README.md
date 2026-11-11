# Gate

![Gate](assets/gate-hero.png)

Kubernetes-native TLS-terminating L7 reverse proxy that selectively exposes
Knative services to the internet. Sits in front of Kourier (Envoy) and closes
domain-fronting vulnerabilities by terminating TLS and strictly enforcing that
the HTTP `Host` / `:authority` matches the negotiated TLS SNI and allowlist.

## How It Works

```text
Internet → [Gate :443] ──── TLS termination ────→ [Kourier/Envoy] → [Knative Service]
                │           SNI == Host check
                │           (421 if mismatch)
                ↑
        SNI/Host allowlist
        & TLS secrets from
        Knative annotations
```

1. Gate watches all Knative Services and DomainMappings for the
   `gate.flaatten.org/expose: "true"` annotation. A DomainMapping needs its own
   annotation; exposing the target Service does not expose its custom domains
2. Gate watches Kubernetes TLS secrets (`kubernetes.io/tls`) and dynamically
   loads and hot-reloads TLS certificates provisioned by Knative/cert-manager
3. Incoming TLS connections: SNI is checked against the allowlist. Unknown or
   unauthorized SNIs are rejected during the TLS handshake
4. For each HTTP request (HTTP/1.1 and HTTP/2 via ALPN), Gate verifies that
   `Host` / `:authority` (port stripped, lowercased) matches the negotiated SNI
   and is present in the allowlist. Any mismatch (such as domain fronting) is
   rejected with `421 Misdirected Request`
5. Legitimate requests are forwarded over TLS to Kourier with connection
   pooling, keep-alive, streaming bodies, WebSocket upgrade support, and
   `X-Forwarded-For` and `X-Forwarded-Proto` headers
6. Incoming plain HTTP connections (:80) are never forwarded: allowlisted hosts
   get a 301 to `https://<host><path>`, non-matching traffic gets 403

## Configuration

| Variable        | Default                      | Description                   |
| --------------- | ---------------------------- | ----------------------------- |
| `UPSTREAM_HOST` | `kourier.kourier-system.svc` | Backend to forward traffic to |
| `UPSTREAM_PORT` | `443`                        | Backend TLS port              |
| `TLS_LISTEN`    | `0.0.0.0:8443`               | TLS proxy listen address      |
| `HTTP_LISTEN`   | `0.0.0.0:8080`               | HTTP redirect listen address  |
| `MAX_CONN`      | `1024`                       | Global concurrent connection cap |
| `MAX_CONN_PER_IP` | `50`                       | Per-client-IP concurrent connection cap |
| `HEALTH_LISTEN` | `0.0.0.0:9090`               | Health check endpoint         |
| `RUST_LOG`      | `gate=info`                  | Log level filter              |

## Exposing a Service

Annotate any Knative Service to make it reachable through gate:

```bash
kubectl annotate ksvc my-service gate.flaatten.org/expose=true
```

Remove the annotation to revoke access:

```bash
kubectl annotate ksvc my-service gate.flaatten.org/expose-
```

Changes take effect immediately — gate watches the Kubernetes API in real time.

## Deploy

Requires a Kubernetes cluster with Knative Serving and Kourier installed.

```bash
mise run build        # Build Docker image and push to registry
mise run deploy       # Deploy to Kubernetes
mise run full-deploy  # Build + deploy
mise run status       # Check deployment status
mise run logs         # Tail logs
mise run delete       # Remove all resources
```

### Kubernetes Resources & RBAC

The deployment creates:

- **Namespace** `gate`
- **ServiceAccount** with ClusterRole to watch Knative Services, DomainMappings,
  and Secrets
- **Deployment** (distroless container, 16-64Mi memory)
- **LoadBalancer Service** on the external MetalLB pool (ports 80, 443)
- **CiliumNetworkPolicy** allowing internet ingress and egress to Kourier, K8s
  API, and DNS

#### RBAC Trade-off on Secrets

Gate requires a `ClusterRole` granting `get`, `list`, and `watch` permissions
on `secrets`:

- **Why not namespaced `Role`?** Knative auto-tls provisions TLS secrets in the
  application namespace where each service resides (`hello`, `varden-blog`,
  etc.). Because services in arbitrary namespaces can be exposed dynamically at
  runtime by adding annotations, static namespaced Roles cannot adapt dynamically
  without additional complex operators.
- **Why not `resourceNames`?** Kubernetes RBAC does not permit `resourceNames`
  restrictions with collection-level `list` or `watch` verbs.
- **In-memory mitigation:** Gate operates strictly read-only, filters in memory
  exclusively for `type: kubernetes.io/tls` (or secrets containing `tls.crt` /
  `tls.key`), and only stores certificates matching allowlisted/exposed
  hostnames.

## Development

```bash
cargo test            # Run unit and integration tests (70 tests)
cargo check           # Type check
cargo clippy          # Lint checks
cargo fmt --check     # Code style check
mise run clean        # Remove build artifacts
```

## Architecture

```text
src/
├── main.rs         # Entrypoint — spawns proxy, controller, and health tasks
├── lib.rs          # Crate root — module declarations and shared Allowlist
├── cert.rs         # Dynamic certificate store, SNI resolver, and X.509 SAN parser
├── upstream.rs     # Upstream TLS connector and connection pool for Kourier
├── proxy.rs        # TLS termination, L7 host validation, HTTP redirect, health
├── sni.rs          # TLS ClientHello SNI parser (legacy helper and tests)
└── controller.rs   # Knative Service/DomainMapping/Secret watcher and hot-reload
```

- **Pure Rust, zero C dependencies** — builds on distroless base image
- **L7 TLS termination** — terminates client TLS, validates Host == SNI (421 on mismatch), and re-encrypts upstream to Kourier
- **Annotation-driven** — no config files or restart needed to change exposed services
- Shared `Allowlist` and `CertStore` connect controller to proxies

## License

MIT
