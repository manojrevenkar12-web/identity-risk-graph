# ADR-0006: The LLM explains and never acts

**Context.** Using an LLM to "auto-remediate" would put a prompt-injectable component in front of
write access to customer estates. Estate data (names, descriptions) is attacker-influenced.

**Decision.** The model (Bedrock, Converse API, in the customer's region) only turns a finding's
facts into prose for a CISO. It has no tools, and its output never reaches the plan or decision
path. A deterministic template is always available as the fallback.

**Consequences.**
- No prompt injection can change access.
- A wrong explanation is a documentation bug, not an incident.
- If agentic triage is added later (for example, suggesting which findings to bundle into a
  plan), its output enters the same reviewed, four-eyes plan flow as a human's.
