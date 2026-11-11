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
2. Gate watches Kubernetes TLS secrets (`type=kubernetes.io/tls`) strictly within
   its own `gate` namespace via a namespaced Role, dynamically loading and
   hot-reloading TLS certificates provisioned by cert-manager
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
| `MAX_CONN`      | `256`                        | Global concurrent connection cap (sized for 128Mi memory limit) |
| `MAX_CONN_PER_IP` | `50`                       | Per-client-IP concurrent connection cap |
| `HEALTH_LISTEN` | `0.0.0.0:9090`               | Health check endpoint         |
| `RUST_LOG`      | `gate=info`                  | Log level filter              |

## Exposing a Service

Exposing a service requires two steps:

### 1. Annotate Service or DomainMapping

Annotate the Knative Service or DomainMapping to add it to Gate's allowlist:

```bash
kubectl annotate ksvc my-service gate.flaatten.org/expose=true
```

To remove access:

```bash
kubectl annotate ksvc my-service gate.flaatten.org/expose-
```

### 2. Add Certificate Manifest in `gate` Namespace

Gate only reads TLS secrets in its own `gate` namespace. Add a cert-manager `Certificate` in `apps/gate/config/certificates.yaml`:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: my-service.fn.flaatten.org
  namespace: gate
spec:
  secretName: my-service.fn.flaatten.org-tls
  issuerRef:
    name: letsencrypt-prod
    kind: ClusterIssuer
  dnsNames:
    - my-service.fn.flaatten.org
```

> [!NOTE]
> If an allowlisted host does not yet have a matching certificate in the `gate` namespace, Gate logs a clear warning:
> `allowlisted host has no matching TLS certificate in gate namespace`
> Client TLS handshakes for that host will fail until the secret is populated.

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
- **ServiceAccount** `gate` with:
  - `ClusterRole`: `services` and `domainmappings` in `serving.knative.dev` (`get`, `list`, `watch`)
  - Namespaced `Role` in namespace `gate`: `secrets` (`get`, `list`, `watch`)
- **Deployment** (distroless container, 16Mi request / 128Mi memory limit)
  - Memory limit is set to 128Mi: at `MAX_CONN=256`, each active TLS + HTTP/2 connection consumes ~200-400 KiB (buffers, rustls sessions, and task state), requiring ~64-100 MiB under peak concurrent load, leaving sufficient headroom for dynamic cert loading and streaming without OOM-killer pressure.
- **LoadBalancer Service** on the external IP pool (ports 80, 443)
- **CiliumNetworkPolicy** allowing internet ingress and egress to Kourier, K8s
  API, and DNS

#### Secret Isolation & Least Privilege

Gate avoids cluster-wide secrets access:
- **Namespaced Role:** Gate reads TLS secrets only within its own `gate` namespace via a namespaced Role and field selector `type=kubernetes.io/tls`.
- **Cert-Manager Provisioning:** Services exposed through Gate have their public certificates explicitly provisioned in `gate` namespace, preventing Gate from accessing application secrets, tokens, or private data in workload namespaces.

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
