// Package synth generates a realistic company's identity estate: an IdP with people and groups,
// AWS roles with real IAM policy documents, a Google-Workspace-style OAuth app inventory, and
// AI agents with owners and keys. It plants a known number of risks of each kind and returns
// them as ground truth, so detection precision and recall can be measured, not asserted.
//
// It also plants near-misses that a naive scanner flags but a correct one must not: admins
// without MFA whose admin policy requires MFA (so they hold no admin access at all), SREs
// without MFA whose role denies everything without MFA, scoped iam:PassRole that cannot
// escalate, verified vendors with broad OAuth scopes, old keys that can only read, people
// who left the company and were deprovisioned properly.
package synth

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/manojrevenkar12-web/identity-risk-graph/internal/awsiam"
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/model"
)

const (
	Domain   = "acme.example"
	External = "partner.example"
	Account  = "111122223333"
)

// Planted counts per rule. Scaled with the org size unless set explicitly.
type Config struct {
	Humans int
	Seed   uint64
	Now    time.Time
}

// Truth is the set of subjects that each rule must flag, and nothing else.
type Truth map[string]map[string]bool

func (t Truth) add(rule, id string) {
	if t[rule] == nil {
		t[rule] = map[string]bool{}
	}
	t[rule][id] = true
}

type gen struct {
	cfg   Config
	r     *rand.Rand
	s     *model.Snapshot
	truth Truth
	seq   map[string]int
}

func Generate(cfg Config) (*model.Snapshot, Truth) {
	if cfg.Humans == 0 {
		cfg.Humans = 2000
	}
	if cfg.Now.IsZero() {
		cfg.Now = time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	}
	prng := rand.New(rand.NewPCG(cfg.Seed, cfg.Seed^0x9e3779b97f4a7c15)) //nolint:gosec // reproducible test data needs a seeded PRNG
	g := &gen{cfg: cfg, r: prng, truth: Truth{}, seq: map[string]int{},
		s: &model.Snapshot{Tenant: "acme", TakenAt: cfg.Now, Policies: map[string][]awsiam.Policy{}, Domain: Domain}}
	g.resources()
	g.roles()
	g.groups()
	g.people()
	g.machines()
	g.oauthApps()
	return g.s, g.truth
}

// ------------------------------------------------------------------------------------- helpers
func (g *gen) id(prefix string) string {
	g.seq[prefix]++
	return fmt.Sprintf("%s-%05d", prefix, g.seq[prefix])
}

func (g *gen) node(n model.Node) string {
	if n.Attrs == nil {
		n.Attrs = map[string]string{}
	}
	g.s.Nodes = append(g.s.Nodes, n)
	return n.ID
}

func (g *gen) edge(from, to string, k model.EdgeKind, attrs map[string]string) {
	g.s.Edges = append(g.s.Edges, model.Edge{From: from, To: to, Kind: k, Attrs: attrs})
}

func (g *gen) daysAgo(lo, hi int) string {
	d := lo + g.r.IntN(hi-lo+1)
	return g.cfg.Now.Add(-time.Duration(d)*24*time.Hour - time.Duration(g.r.IntN(86400))*time.Second).Format(time.RFC3339)
}

func pol(name, doc string) awsiam.Policy {
	var p awsiam.Policy
	if err := json.Unmarshal([]byte(doc), &p); err != nil {
		panic(fmt.Sprintf("policy %s: %v", name, err))
	}
	if err := p.Validate(); err != nil {
		panic(fmt.Sprintf("policy %s: %v", name, err))
	}
	p.Name = name
	return p
}

// ------------------------------------------------------------------------------------- estate
var resourceSpec = []struct {
	name, typ, env string
	crown          bool
}{
	{"prod-customer-data", "s3", "prod", true}, {"prod-payments-exports", "s3", "prod", true}, {"prod-app-logs", "s3", "prod", false},
	{"analytics-raw", "s3", "prod", false}, {"dev-sandbox", "s3", "dev", false}, {"build-artifacts", "s3", "prod", false},
	{"prod-core", "rds", "prod", true}, {"staging-core", "rds", "staging", false},
	{"prod/payments-api-key", "secret", "prod", true}, {"prod/db-master", "secret", "prod", true}, {"prod/support-desk-token", "secret", "prod", false}, {"dev/test-key", "secret", "dev", false},
	{"org-trail", "trail", "prod", true}, {"prod-data-key", "kms", "prod", true},
}

func arnOf(name, typ string) string {
	switch typ {
	case "s3":
		return "arn:aws:s3:::" + name
	case "rds":
		return "arn:aws:rds-db:eu-central-1:" + Account + ":dbuser:" + name + "/app"
	case "secret":
		return "arn:aws:secretsmanager:eu-central-1:" + Account + ":secret:" + name
	case "trail":
		return "arn:aws:cloudtrail:eu-central-1:" + Account + ":trail/" + name
	default:
		return "arn:aws:kms:eu-central-1:" + Account + ":key/" + name
	}
}

func (g *gen) resources() {
	for _, r := range resourceSpec {
		attrs := map[string]string{model.AttrARN: arnOf(r.name, r.typ), model.AttrResType: r.typ, model.AttrEnv: r.env}
		if r.crown {
			attrs[model.AttrCrownJewel] = "true"
		}
		g.node(model.Node{ID: "res:" + r.name, Kind: model.Resource, Name: r.name, Source: "aws", Attrs: attrs})
	}
}

const protectAudit = `{"Version":"2012-10-17","Statement":[{"Sid":"ProtectAuditAndKeys","Effect":"Deny",
 "Action":["cloudtrail:StopLogging","cloudtrail:DeleteTrail","kms:ScheduleKeyDeletion"],"Resource":"*"}]}`

func (g *gen) roles() {
	a := Account
	roles := map[string][]awsiam.Policy{
		"ReadOnly": {pol("ReadOnly", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:Get*","s3:List*"],"Resource":["arn:aws:s3:::dev-*","arn:aws:s3:::dev-*/*","arn:aws:s3:::analytics-raw","arn:aws:s3:::analytics-raw/*"]},
			{"Effect":"Allow","Action":"rds-db:connect","Resource":"arn:aws:rds-db:eu-central-1:`+a+`:dbuser:staging-core/*"}]}`)},
		"Developer": {pol("Developer", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":["arn:aws:s3:::dev-*","arn:aws:s3:::dev-*/*"]},
			{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"arn:aws:s3:::analytics-raw/*"},
			{"Effect":"Allow","Action":"rds-db:connect","Resource":"arn:aws:rds-db:eu-central-1:`+a+`:dbuser:staging-core/*"},
			{"Effect":"Allow","Action":"secretsmanager:GetSecretValue","Resource":"arn:aws:secretsmanager:eu-central-1:`+a+`:secret:dev/*"}]}`)},
		"DataEngineer": {pol("DataEngineer", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":["arn:aws:s3:::prod-customer-data/*","arn:aws:s3:::analytics-raw/*"]},
			{"Effect":"Allow","Action":"rds-db:connect","Resource":"arn:aws:rds-db:eu-central-1:`+a+`:dbuser:prod-core/*"}]}`)},
		// SRE: everything but IAM, never without MFA, never the audit trail
		"SRE": {pol("SRE", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","NotAction":["iam:*","organizations:*"],"Resource":"*"}]}`),
			pol("RequireMFA", `{"Version":"2012-10-17","Statement":[{"Sid":"DenyWithoutMFA","Effect":"Deny","NotAction":["iam:ChangePassword","sts:GetSessionToken"],"Resource":"*","Condition":{"BoolIfExists":{"aws:MultiFactorAuthPresent":"false"}}}]}`),
			pol("ProtectAudit", protectAudit)},
		// admin only with MFA: the Allow itself carries the condition
		"PlatformAdmin": {pol("PlatformAdmin", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}}]}`),
			pol("ProtectAudit", protectAudit)},
		"BreakGlass": {pol("BreakGlass", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`)},
		"AppRuntime": {pol("AppRuntime", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:PutObject"],"Resource":"arn:aws:s3:::prod-app-logs/*"},
			{"Effect":"Allow","Action":"secretsmanager:GetSecretValue","Resource":"arn:aws:secretsmanager:eu-central-1:`+a+`:secret:prod/support-*"}]}`)},
		"ReportingRead": {pol("ReportingRead", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::analytics-raw/*"}]}`)},
		"EtlWriter":     {pol("EtlWriter", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject","s3:DeleteObject"],"Resource":"arn:aws:s3:::analytics-raw/*"}]}`)},
		// deploys may pass only the application roles: scoped PassRole is not escalation
		"Deployer": {pol("Deployer", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ecs:*","lambda:UpdateFunctionCode"],"Resource":"*"},
			{"Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::`+a+`:role/app-*"},{"Effect":"Allow","Action":"s3:PutObject","Resource":"arn:aws:s3:::build-artifacts/*"}]}`)},
		"AgentReadOnly": {pol("AgentReadOnly", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"arn:aws:s3:::analytics-raw/*"},
			{"Effect":"Allow","Action":"rds-db:connect","Resource":"arn:aws:rds-db:eu-central-1:`+a+`:dbuser:staging-core/*"}]}`)},
		// ---- misconfigurations the generator plants ----
		"DeveloperLegacy": {pol("DeveloperLegacy", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:*","iam:*"],"Resource":"*"}]}`)},
		"OpsAutomation":   {pol("OpsAutomation", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:*","cloudtrail:*"],"Resource":"*"}]}`)},
		"CIRunner":        {pol("CIRunner", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:PutObject","Resource":"arn:aws:s3:::build-artifacts/*"}]}`)},
		"InfraAdmin":      {pol("InfraAdmin", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`)},
		"AgentOps": {pol("AgentOps", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:*"],"Resource":["arn:aws:s3:::prod-customer-data","arn:aws:s3:::prod-customer-data/*"]},
			{"Effect":"Allow","Action":"rds:DeleteDBInstance","Resource":"*"}]}`)},
	}
	for name, ps := range roles {
		id := "role:" + name
		g.node(model.Node{ID: id, Kind: model.Role, Name: name, Source: "aws", Attrs: map[string]string{model.AttrARN: "arn:aws:iam::" + a + ":role/" + name}})
		g.s.Policies[id] = ps
	}
	// trust: CI can assume InfraAdmin (a planted chain), deploys can assume Deployer (fine)
	g.edge("role:CIRunner", "role:InfraAdmin", model.CanAssume, nil)
	g.edge("role:CIRunner", "role:Deployer", model.CanAssume, nil)
}

var departments = []struct {
	name, role string
	weight     int
}{
	{"engineering", "Developer", 30}, {"data", "DataEngineer", 8}, {"sre", "SRE", 5}, {"support", "ReadOnly", 20},
	{"sales", "", 22}, {"finance", "", 8}, {"people", "", 7},
}

func (g *gen) groups() {
	for _, d := range departments {
		id := "grp:" + d.name
		g.node(model.Node{ID: id, Kind: model.Group, Name: d.name, Source: "idp"})
		if d.role != "" {
			g.edge(id, "role:"+d.role, model.Assigned, nil)
		}
	}
	g.node(model.Node{ID: "grp:platform-admins", Kind: model.Group, Name: "platform-admins", Source: "idp", Attrs: map[string]string{"privileged": "true"}})
	g.edge("grp:platform-admins", "role:PlatformAdmin", model.Assigned, nil)
	g.node(model.Node{ID: "grp:legacy-devs", Kind: model.Group, Name: "legacy-devs", Source: "idp"})
	g.edge("grp:legacy-devs", "role:DeveloperLegacy", model.Assigned, nil)
	g.node(model.Node{ID: "grp:contractors-data", Kind: model.Group, Name: "contractors-data", Source: "idp"})
	g.edge("grp:contractors-data", "role:DataEngineer", model.Assigned, nil)
}

func (g *gen) human(dept string, mfa bool, attrs map[string]string) string {
	id := g.id("usr")
	a := map[string]string{model.AttrStatus: "active", model.AttrHRStatus: "employed", model.AttrMFA: fmt.Sprint(mfa),
		model.AttrLastSeen: g.daysAgo(0, 20), model.AttrEmailDomain: Domain, "department": dept}
	for k, v := range attrs {
		a[k] = v
	}
	g.node(model.Node{ID: id, Kind: model.Human, Name: id + "@" + a[model.AttrEmailDomain], Source: "idp", Attrs: a})
	if dept != "" {
		g.edge(id, "grp:"+dept, model.MemberOf, nil)
	}
	return id
}

func scaled(n, per int) int { return max(2, n/per) }

func (g *gen) people() {
	n := g.cfg.Humans
	total := 0
	for _, d := range departments {
		total += d.weight
	}
	// the ordinary population: departments by weight; MFA off only where it cannot matter
	noMFAok := map[string]bool{"support": true, "sales": true, "finance": true, "people": true, "engineering": true, "sre": true}
	for _, d := range departments {
		for i := 0; i < n*d.weight/total; i++ {
			mfa := !(noMFAok[d.name] && g.r.Float64() < 0.08)
			g.human(d.name, mfa, nil)
		}
	}
	// admins: most with MFA; some without MFA, who hold NO admin access because the policy needs MFA
	for i := 0; i < scaled(n, 200); i++ {
		u := g.human("sre", true, nil)
		g.edge(u, "grp:platform-admins", model.MemberOf, nil)
	}
	for i := 0; i < scaled(n, 600); i++ {
		u := g.human("support", false, nil) // near miss: no MFA + admin group, but PlatformAdmin requires MFA
		g.edge(u, "grp:platform-admins", model.MemberOf, nil)
	}
	g.node(model.Node{ID: "usr-breakglass", Kind: model.Human, Name: "breakglass@" + Domain, Source: "idp",
		Attrs: map[string]string{model.AttrStatus: "active", model.AttrHRStatus: "employed", model.AttrMFA: "true", model.AttrLastSeen: g.daysAgo(200, 300),
			model.AttrEmailDomain: Domain, model.AttrBreakGlass: "true"}})
	g.edge("usr-breakglass", "role:BreakGlass", model.Assigned, nil)

	// planted: offboarding gap (left the company, IdP account still active), and its near miss
	for i := 0; i < scaled(n, 100); i++ {
		g.truth.add("offboarding_gap", g.human([]string{"support", "sales", "finance"}[i%3], true, map[string]string{model.AttrHRStatus: "terminated"}))
	}
	for i := 0; i < scaled(n, 100); i++ {
		g.human("engineering", true, map[string]string{model.AttrHRStatus: "terminated", model.AttrStatus: "deprovisioned"})
	}
	// planted: dormant people who can still change production
	for i := 0; i < scaled(n, 150); i++ {
		g.truth.add("dormant_privileged", g.human("sre", true, map[string]string{model.AttrLastSeen: g.daysAgo(120, 400)}))
	}
	for i := 0; i < scaled(n, 150); i++ { // near miss: dormant but harmless
		g.human("support", true, map[string]string{model.AttrLastSeen: g.daysAgo(120, 400)})
	}
	// planted: no MFA but real production write access (DataEngineer has no MFA condition)
	for i := 0; i < scaled(n, 200); i++ {
		g.truth.add("privileged_without_mfa", g.human("data", false, nil))
	}
	// planted: escalation through the legacy role with iam:*
	for i := 0; i < scaled(n, 250); i++ {
		u := g.human("engineering", true, nil)
		g.edge(u, "grp:legacy-devs", model.MemberOf, nil)
		g.truth.add("privilege_escalation", u)
	}
	// planted: external contractors writing customer data; near miss: contractors on dev only
	for i := 0; i < scaled(n, 300); i++ {
		u := g.human("", true, map[string]string{model.AttrEmailDomain: External})
		g.edge(u, "grp:contractors-data", model.MemberOf, nil)
		g.truth.add("external_privileged", u)
	}
	for i := 0; i < scaled(n, 100); i++ {
		g.human("engineering", true, map[string]string{model.AttrEmailDomain: External})
	}
}

func (g *gen) machine(kind model.Kind, role string, owner bool, keyAge [2]int, attrs map[string]string) string {
	prefix := map[model.Kind]string{model.Service: "svc", model.Agent: "agt"}[kind]
	id := g.id(prefix)
	a := map[string]string{model.AttrStatus: "active", model.AttrKeyCreated: g.daysAgo(keyAge[0], keyAge[1]), model.AttrKeyLastUsed: g.daysAgo(0, 3), model.AttrLastSeen: g.daysAgo(0, 2)}
	for k, v := range attrs {
		a[k] = v
	}
	g.node(model.Node{ID: id, Kind: kind, Name: id, Source: map[model.Kind]string{model.Service: "aws", model.Agent: "agents"}[kind], Attrs: a})
	if role != "" {
		g.edge(id, "role:"+role, model.Assigned, nil)
	}
	if owner {
		g.edge(fmt.Sprintf("usr-%05d", 1+g.r.IntN(g.seq["usr"])), id, model.Owns, nil)
	}
	return id
}

func (g *gen) machines() {
	n := g.cfg.Humans
	fresh, old := [2]int{1, 80}, [2]int{200, 700}
	for i := 0; i < scaled(n, 40); i++ {
		g.machine(model.Service, "AppRuntime", true, fresh, nil)
	}
	for i := 0; i < scaled(n, 120); i++ { // near miss: old key, read-only
		g.machine(model.Service, "ReportingRead", true, old, nil)
	}
	for i := 0; i < scaled(n, 120); i++ {
		g.truth.add("stale_credential", g.machine(model.Service, "EtlWriter", true, old, nil))
	}
	for i := 0; i < scaled(n, 300); i++ {
		g.truth.add("toxic_combination", g.machine(model.Service, "OpsAutomation", true, fresh, nil))
	}
	for i := 0; i < scaled(n, 400); i++ { // CI can assume InfraAdmin: it can escalate AND write prod while erasing the trail
		ci := g.machine(model.Service, "CIRunner", true, fresh, map[string]string{"purpose": "ci"})
		g.truth.add("privilege_escalation", ci)
		g.truth.add("toxic_combination", ci)
	}
	// AI agents: most read-only and owned; planted unowned ones and destructive ones
	for i := 0; i < scaled(n, 25); i++ {
		g.machine(model.Agent, "AgentReadOnly", true, fresh, map[string]string{"framework": []string{"langgraph", "bedrock-agents", "custom"}[i%3]})
	}
	for i := 0; i < scaled(n, 200); i++ {
		g.truth.add("ai_agent_risk", g.machine(model.Agent, "AgentReadOnly", false, fresh, nil))
	}
	for i := 0; i < scaled(n, 250); i++ {
		g.truth.add("ai_agent_risk", g.machine(model.Agent, "AgentOps", true, fresh, nil))
	}
}

var (
	lowScopes  = []string{"openid", "email", "profile", "calendar.readonly", "drive.file"}
	highScopes = []string{"https://mail.google.com/", "drive", "admin.directory.user", "gmail.modify"}
)

func (g *gen) oauthApps() {
	n := g.cfg.Humans
	users := g.seq["usr"]
	grant := func(app string, scopes []string, k int) {
		for i := 0; i < k; i++ {
			g.edge(fmt.Sprintf("usr-%05d", 1+g.r.IntN(users)), app, model.Granted, map[string]string{"scopes": join(scopes)})
		}
	}
	app := func(verified bool, scopes []string, planted bool) {
		id := g.id("app")
		g.node(model.Node{ID: id, Kind: model.OAuthApp, Name: id, Source: "workspace", Attrs: map[string]string{model.AttrVerified: fmt.Sprint(verified), "scopes": join(scopes)}})
		grant(id, scopes, 1+g.r.IntN(max(2, n/50)))
		if planted {
			g.truth.add("risky_oauth_app", id)
		}
	}
	for i := 0; i < scaled(n, 80); i++ {
		app(g.r.Float64() < 0.8, []string{lowScopes[g.r.IntN(len(lowScopes))], "email"}, false) // includes unverified low-risk: near misses
	}
	for i := 0; i < scaled(n, 400); i++ {
		app(true, []string{highScopes[g.r.IntN(len(highScopes))]}, false) // verified vendor, broad scope: near miss
	}
	for i := 0; i < scaled(n, 250); i++ {
		app(false, []string{highScopes[g.r.IntN(len(highScopes))], "email"}, true)
	}
}

func join(s []string) string {
	out := ""
	for i, v := range s {
		if i > 0 {
			out += " "
		}
		out += v
	}
	return out
}
