// Package awsiam evaluates AWS IAM identity policies the way AWS does, for the subset of the
// language that decides most real access questions:
//
//   - Effect Allow/Deny, Action/NotAction, Resource/NotResource with * and ? wildcards
//     (actions case-insensitive, resources case-sensitive);
//   - an explicit Deny anywhere wins over any Allow; no matching Allow is an implicit deny;
//   - Condition operators: String{Equals,NotEquals,Like,NotLike}, Bool, Arn{Equals,Like},
//     Numeric{Equals,LessThan,LessThanEquals,GreaterThan,GreaterThanEquals}, IpAddress,
//     NotIpAddress, Null, each with the ...IfExists suffix; multiple keys and operators in one
//     block are ANDed, multiple values for one key are ORed.
//
// Not modelled (and documented in docs/ARCHITECTURE.md): resource-based policies, session
// policies, permission boundaries and SCPs as separate layers (they can be expressed as Deny
// statements in the identity's policy set), policy variables, and ForAllValues/ForAnyValue.
// An unknown condition operator never matches: a statement we cannot evaluate grants nothing.
package awsiam

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// StringList accepts both "a" and ["a", "b"], as IAM JSON does.
type StringList []string

func (s *StringList) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*s = StringList{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return fmt.Errorf("expected string or list of strings: %w", err)
	}
	*s = many
	return nil
}

type Statement struct {
	Sid         string                           `json:"Sid,omitempty"`
	Effect      string                           `json:"Effect"`
	Action      StringList                       `json:"Action,omitempty"`
	NotAction   StringList                       `json:"NotAction,omitempty"`
	Resource    StringList                       `json:"Resource,omitempty"`
	NotResource StringList                       `json:"NotResource,omitempty"`
	Condition   map[string]map[string]StringList `json:"Condition,omitempty"`
}

type Policy struct {
	Name      string      `json:"-"`
	Version   string      `json:"Version"`
	Statement []Statement `json:"Statement"`
}

// UnmarshalJSON also accepts a single statement object instead of a list.
func (p *Policy) UnmarshalJSON(b []byte) error {
	var raw struct {
		Version   string          `json:"Version"`
		Statement json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	p.Version = raw.Version
	if len(raw.Statement) > 0 && raw.Statement[0] == '{' {
		var s Statement
		if err := json.Unmarshal(raw.Statement, &s); err != nil {
			return err
		}
		p.Statement = []Statement{s}
		return nil
	}
	return json.Unmarshal(raw.Statement, &p.Statement)
}

// Validate rejects documents AWS would reject, so a malformed policy fails loudly at ingest.
func (p Policy) Validate() error {
	if p.Version != "2012-10-17" && p.Version != "2008-10-17" && p.Version != "" {
		return fmt.Errorf("unsupported policy version %q", p.Version)
	}
	for i, s := range p.Statement {
		if s.Effect != "Allow" && s.Effect != "Deny" {
			return fmt.Errorf("statement %d: Effect must be Allow or Deny", i)
		}
		if (len(s.Action) == 0) == (len(s.NotAction) == 0) {
			return fmt.Errorf("statement %d: exactly one of Action or NotAction is required", i)
		}
		if (len(s.Resource) == 0) == (len(s.NotResource) == 0) {
			return fmt.Errorf("statement %d: exactly one of Resource or NotResource is required", i)
		}
	}
	return nil
}

// Request is one access question: may this action be performed on this resource, in this context?
type Request struct {
	Action   string
	Resource string
	Context  map[string]string // condition keys, e.g. aws:MultiFactorAuthPresent=true
}

type Decision struct {
	Allowed bool
	Reason  string // "explicit deny by <policy>/<sid>", "allowed by <policy>/<sid>", "implicit deny"
}

// Evaluate applies AWS's evaluation logic to a set of identity policies.
func Evaluate(policies []Policy, r Request) Decision {
	var allow *Decision
	for _, p := range policies {
		for i, s := range p.Statement {
			if !s.matches(r) {
				continue
			}
			label := fmt.Sprintf("%s/%s", p.Name, sidOr(s.Sid, i))
			if s.Effect == "Deny" {
				return Decision{Allowed: false, Reason: "explicit deny by " + label}
			}
			if allow == nil {
				allow = &Decision{Allowed: true, Reason: "allowed by " + label}
			}
		}
	}
	if allow != nil {
		return *allow
	}
	return Decision{Allowed: false, Reason: "implicit deny"}
}

func sidOr(sid string, i int) string {
	if sid != "" {
		return sid
	}
	return "stmt" + strconv.Itoa(i)
}

func (s Statement) matches(r Request) bool {
	if len(s.Action) > 0 && !anyMatch(s.Action, r.Action, true) {
		return false
	}
	if len(s.NotAction) > 0 && anyMatch(s.NotAction, r.Action, true) {
		return false
	}
	if len(s.Resource) > 0 && !anyMatch(s.Resource, r.Resource, false) {
		return false
	}
	if len(s.NotResource) > 0 && anyMatch(s.NotResource, r.Resource, false) {
		return false
	}
	for op, keys := range s.Condition {
		for key, values := range keys {
			if !conditionHolds(op, key, values, r.Context) {
				return false
			}
		}
	}
	return true
}

func anyMatch(patterns []string, value string, foldCase bool) bool {
	for _, p := range patterns {
		if foldCase {
			if Wildcard(strings.ToLower(p), strings.ToLower(value)) {
				return true
			}
		} else if Wildcard(p, value) {
			return true
		}
	}
	return false
}

// Wildcard matches IAM-style patterns: * is any run of characters (including ":" and "/"),
// ? is exactly one character. Iterative, linear in practice, no regex compilation.
func Wildcard(pattern, s string) bool {
	p, i := 0, 0
	star, mark := -1, 0
	for i < len(s) {
		switch {
		case p < len(pattern) && pattern[p] == '*': // before literal equality: a "*" in s is not special
			star, mark = p, i
			p++
		case p < len(pattern) && (pattern[p] == '?' || pattern[p] == s[i]):
			p++
			i++
		case star >= 0:
			p = star + 1
			mark++
			i = mark
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

func conditionHolds(op, key string, values []string, ctx map[string]string) bool {
	ifExists := strings.HasSuffix(op, "IfExists")
	base := strings.TrimSuffix(op, "IfExists")
	// condition keys are case-insensitive in IAM
	actual, present := "", false
	for k, v := range ctx {
		if strings.EqualFold(k, key) {
			actual, present = v, true
			break
		}
	}
	if base == "Null" {
		want := len(values) > 0 && strings.EqualFold(values[0], "true")
		return want == !present
	}
	if !present {
		return ifExists
	}
	negated := base == "StringNotEquals" || base == "StringNotLike" || base == "NotIpAddress" || base == "ArnNotEquals" || base == "ArnNotLike"
	hit := false
	for _, v := range values {
		if m, ok := compare(base, actual, v); !ok {
			return false // unknown operator or unparsable value: the statement cannot apply
		} else if m {
			hit = true
			break
		}
	}
	if negated {
		return !hit
	}
	return hit
}

// compare returns (matches, understood).
func compare(op, actual, want string) (bool, bool) {
	switch op {
	case "StringEquals", "StringNotEquals", "ArnEquals", "ArnNotEquals":
		return actual == want, true
	case "StringEqualsIgnoreCase":
		return strings.EqualFold(actual, want), true
	case "StringLike", "StringNotLike", "ArnLike", "ArnNotLike":
		return Wildcard(want, actual), true
	case "Bool":
		return strings.EqualFold(actual, want), true
	case "NumericEquals", "NumericLessThan", "NumericLessThanEquals", "NumericGreaterThan", "NumericGreaterThanEquals":
		a, err1 := strconv.ParseFloat(actual, 64)
		w, err2 := strconv.ParseFloat(want, 64)
		if err1 != nil || err2 != nil {
			return false, false
		}
		switch op {
		case "NumericEquals":
			return a == w, true
		case "NumericLessThan":
			return a < w, true
		case "NumericLessThanEquals":
			return a <= w, true
		case "NumericGreaterThan":
			return a > w, true
		default:
			return a >= w, true
		}
	case "IpAddress", "NotIpAddress":
		ip, err := netip.ParseAddr(actual)
		if err != nil {
			return false, false
		}
		pfx, err := netip.ParsePrefix(want)
		if err != nil {
			addr, err2 := netip.ParseAddr(want)
			if err2 != nil {
				return false, false
			}
			return addr == ip, true
		}
		return pfx.Contains(ip), true
	}
	return false, false
}
