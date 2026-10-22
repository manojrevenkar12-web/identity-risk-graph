# ADR-0003: In-memory graph over snapshots, not a graph database

**Context.** Identity data is a graph, and Neo4j or Neptune is the obvious buy. But the heavy
question, "what can every identity effectively do?", is a batch computation over one consistent
snapshot. It needs IAM policy evaluation in each authentication context, which no graph database
does natively.

**Decision.** Store each sync as a snapshot (jsonb), and build the graph in memory for analysis
and for the decision point. Role grants are computed once per (role, context) and shared.

**Consequences.**
- One datastore to secure, back up, encrypt and audit.
- Measured: 0.96 s and 244 MB for a 50,000-person company (`reports/scale.json`).
- Ad-hoc graph exploration across history, such as "who could reach X last March?", is not
  served. If customers ask for it, add a graph store fed from the same snapshots; the analysis
  code does not change.
