# ADR-0001: One Go binary, modular packages, two run modes

**Context.** Five engineers, one product, a SOC 2 audit coming. Every extra deployable means
another pipeline, another threat-model entry and another on-call surface.

**Decision.** A single `irg` binary with strict package boundaries:
- `awsiam`, `graph` and `risk` are pure and have no I/O;
- `store` owns SQL;
- `connector` owns network calls to customer estates;
- `app` wires them together.

It runs as `api`, `worker` or `all`. Go, because the work is concurrent, CPU-bound graph
analysis plus network I/O, and because a static binary on distroless is a very small attack
surface.

**Consequences.**
- One build, one image, one version in every log line.
- The API and workers scale independently, as two Deployments of the same image.
- When a module needs its own release cadence (likely the connectors, as their number grows), it
  can be split along the existing package boundary.
