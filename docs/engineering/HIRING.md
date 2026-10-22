# Growing the team from 5 to 20

## Shape

| Engineers | Teams | Why this shape |
|---|---|---|
| 5 (today) | one team, everyone on everything; on-call shared | not enough people to split, and everyone should know the whole system |
| 8–10 | **Platform** (API, tenancy, auth, deploy, decision point) and **Detection** (graph, IAM semantics, rules, connectors) | the two halves change for different reasons and need different expertise |
| 14–16 | add **Connectors & Enforcement** (one integration ships a week, safely) | connectors become the growth bottleneck; enforcement safety needs owners |
| 20 | add **AI Agent Security** (decision point, JIT, agent discovery) as its own team; a dedicated **Security Engineer** | the agent-governance market moves fastest; we need our own red team |

Each team has 4–6 engineers, a tech lead who still writes code, and a written charter. Engineering
managers are added from about 12 engineers, so tech leads are not carrying everyone's 1:1s.

## Hiring order (next 12 months)

1. **Senior backend engineer, Go**, for Platform. Tenancy, auth and the job system need a second
   owner.
2. **Senior engineer with deep AWS IAM / identity knowledge**, for Detection. Policy semantics
   are the moat.
3. **Connector engineer** with experience of SaaS APIs (Okta, Entra ID, Google Workspace, GitHub).
4. **SRE / platform engineer.** EKS, Terraform, observability, the SOC 2 evidence pipeline.
5. **Security engineer**: threat modelling, pen-test coordination, detection content.
6. Then engineers into the teams, in proportion to the roadmap.

## The bar and the loop (4 stages, under 2 weeks)

| Stage | What we learn | How |
|---|---|---|
| 30 min call with the hiring manager | motivation, scope fit, what they want to own | conversation, no trivia |
| 90 min working session on real code | how they read, change and test unfamiliar code | a trimmed copy of this repository: fix a planted bug in the IAM evaluator, then add a rule with tests. Paid if take-home |
| 60 min system design | trade-offs under constraints | "Add a connector that reaches 10M identities", or "make decisions consistent across regions" |
| 45 min values, with a founder | ownership, low ego, how they handle being wrong | past incidents they owned, disagreements they lost |

- **Decisions.** Made within 48 hours by a written panel debrief. Every interviewer submits
  feedback before reading the others'. One strong "no" needs a reason tied to the role's
  scorecard.
- **The bar is written down** per role: three must-haves and two nice-to-haves. "Culture fit"
  is not a criterion. "Raises the average of the team on at least one must-have" is.

## Onboarding (first 30 days)

- **Day 1:** laptop, access through the JIT flow, a deploy of a one-line change to production
  with a buddy.
- **Week 1:** read the ADRs and the threat model; pair on one PR in each team.
- **Week 2–4:** own one small feature end to end; shadow one on-call week.
- **Day 30:** a 1:1 retrospective of onboarding itself. What was unclear gets fixed in the docs
  by the new person.
