# Gate

![Gate](assets/gate-hero.png)

Kubernetes-native L4 gateway that selectively exposes Knative services to the
internet. Sits in front of Kourier (Envoy) and filters traffic based on TLS SNI
and HTTP Host headers against a dynamic allowlist built from Knative Service
annotations.

## How It Works

```text
Internet → [Gate :443/:80] → [Kourier/Envoy] → [Knative Service]
                ↑
        SNI/Host allowlist
        built from Knative
        Service annotations
```

1. Gate watches all Knative Services for the `gate.flaatten.org/expose: "true"`
   annotation
2. Annotated services have their hostname (from `.status.url`) added to the
   allowlist
3. Incoming TLS connections: SNI is extracted from the ClientHello and checked
   against the allowlist before forwarding to Kourier
4. Incoming HTTP connections: the Host header is checked before forwarding
5. Non-matching traffic is silently dropped (TLS) or rejected with 403 (HTTP)

No TLS termination — gate operates at L4 and passes through encrypted traffic
unchanged.

## Configuration

| Variable        | Default                      | Description                   |
| --------------- | ---------------------------- | ----------------------------- |
| `UPSTREAM_HOST` | `kourier.kourier-system.svc` | Backend to forward traffic to |
| `TLS_LISTEN`    | `0.0.0.0:8443`               | TLS proxy listen address      |
| `HTTP_LISTEN`   | `0.0.0.0:8080`               | HTTP proxy listen address     |
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

### Kubernetes Resources

The deployment creates:

- **Namespace** `gate`
- **ServiceAccount** with ClusterRole to watch Knative Services
- **Deployment** (distroless container, 16-64Mi memory)
- **LoadBalancer Service** on the external MetalLB pool (ports 80, 443)
- **CiliumNetworkPolicy** allowing internet ingress and egress to Kourier, K8s
  API, and DNS

## Development

```bash
cargo test            # Run tests (56 tests)
cargo check           # Type check
cargo build           # Debug build
mise run clean        # Remove build artifacts
```

## Architecture

```text
src/
├── main.rs         # Entrypoint — spawns proxy, controller, and health tasks
├── lib.rs          # Crate root — shared Allowlist type, module declarations
├── sni.rs          # TLS ClientHello parser — extracts SNI hostname
├── proxy.rs        # TCP proxy (TLS + HTTP) and health server
└── controller.rs   # Knative Service watcher — builds allowlist from annotations
```

- **Pure Rust, zero C dependencies** — builds on distroless base image
- **L4 passthrough** — no TLS termination, no certificate management
- **Annotation-driven** — no config files or restart needed to change exposed
  services
- Shared `Allowlist` (`Arc<RwLock<HashSet<String>>>`) connects controller to
  proxies

## License

MIT
