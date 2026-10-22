// Package model is the identity graph's vocabulary, shared by connectors, storage and analysis.
//
// Nodes are things that can act (people, service accounts, AI agents, OAuth apps), things that
// bundle access (groups, roles) and things worth protecting (resources). Edges say how access
// flows between them. Access to a resource is never an edge: it is computed from roles' IAM
// policies at analysis time, so the answer always reflects the policy text actually in force.
package model

import (
	"encoding/json"
	"time"

	"github.com/manojrevenkar12-web/identity-risk-graph/internal/awsiam"
)

type Kind string

const (
	Human    Kind = "human"
	Service  Kind = "service_account"
	Agent    Kind = "ai_agent"
	OAuthApp Kind = "oauth_app"
	Group    Kind = "group"
	Role     Kind = "role"
	Resource Kind = "resource"
)

// Actor kinds can authenticate and act.
func (k Kind) Actor() bool { return k == Human || k == Service || k == Agent || k == OAuthApp }

type EdgeKind string

const (
	MemberOf  EdgeKind = "member_of"  // actor → group
	Assigned  EdgeKind = "assigned"   // actor/group → role (IdP-to-AWS assignment)
	CanAssume EdgeKind = "can_assume" // role → role (trust policy allows sts:AssumeRole)
	Granted   EdgeKind = "granted"    // human → oauth_app (consent; Attrs["scopes"])
	Owns      EdgeKind = "owns"       // human → service account / agent (accountable owner)
)

type Node struct {
	ID     string            `json:"id"`
	Kind   Kind              `json:"kind"`
	Name   string            `json:"name"`
	Source string            `json:"source"` // which connector produced it: idp, aws, workspace, agents
	Attrs  map[string]string `json:"attrs,omitempty"`
}

// Attribute keys used across connectors and detectors.
const (
	AttrStatus      = "status"       // active | suspended | deprovisioned
	AttrHRStatus    = "hr_status"    // employed | terminated (from the HR system)
	AttrMFA         = "mfa"          // true | false
	AttrLastSeen    = "last_seen"    // RFC 3339
	AttrEmailDomain = "email_domain" // for external identities
	AttrCrownJewel  = "crown_jewel"  // true on resources whose compromise is a company-level incident
	AttrARN         = "arn"
	AttrResType     = "resource_type" // s3 | rds | secret | trail | kms
	AttrEnv         = "env"           // prod | staging | dev
	AttrKeyCreated  = "key_created"   // RFC 3339, long-lived credential creation
	AttrKeyLastUsed = "key_last_used" // RFC 3339
	AttrVerified    = "publisher_verified"
	AttrBreakGlass  = "break_glass" // never auto-remediated
	AttrQuarantined = "quarantined"
)

type Edge struct {
	From  string            `json:"from"`
	To    string            `json:"to"`
	Kind  EdgeKind          `json:"kind"`
	Attrs map[string]string `json:"attrs,omitempty"`
}

// Snapshot is everything one sync saw for one tenant.
type Snapshot struct {
	Tenant   string                     `json:"tenant"`
	TakenAt  time.Time                  `json:"taken_at"`
	Nodes    []Node                     `json:"nodes"`
	Edges    []Edge                     `json:"edges"`
	Policies map[string][]awsiam.Policy `json:"policies"` // role ID → its identity policies
	Domain   string                     `json:"domain"`   // the company's own email domain
}

// Severity of a finding, ordered.
type Severity string

const (
	Critical Severity = "critical"
	High     Severity = "high"
	Medium   Severity = "medium"
	Low      Severity = "low"
)

func (s Severity) Weight() float64 {
	switch s {
	case Critical:
		return 1.0
	case High:
		return 0.7
	case Medium:
		return 0.4
	default:
		return 0.15
	}
}

// Action is a remediation a connector can carry out, and undo.
type Action struct {
	Type   string            `json:"type"` // suspend_user | remove_membership | revoke_grant | deactivate_key | quarantine_agent | unassign_role
	Target string            `json:"target"`
	From   string            `json:"from,omitempty"` // the group/role/app the target is removed from
	Data   map[string]string `json:"data,omitempty"` // what an undo needs (e.g. the scopes of a revoked grant)
}

type Finding struct {
	ID          string   `json:"id"` // stable: rule + subject (+ object), so re-runs update, not duplicate
	Rule        string   `json:"rule"`
	Severity    Severity `json:"severity"`
	Score       float64  `json:"score"` // 0-100
	Subject     string   `json:"subject"`
	SubjectKind Kind     `json:"subject_kind"`
	Title       string   `json:"title"`
	Evidence    []string `json:"evidence"`     // human-readable path and facts
	BlastRadius int      `json:"blast_radius"` // crown-jewel resources this identity can reach
	Controls    []string `json:"controls"`     // SOC 2 / ISO 27001 control IDs this violates
	Remediation []Action `json:"remediation"`
}

func (f Finding) JSON() []byte {
	b, _ := json.Marshal(f)
	return b
}
