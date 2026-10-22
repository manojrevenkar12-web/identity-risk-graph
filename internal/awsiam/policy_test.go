package awsiam

import (
	"encoding/json"
	"testing"
)

func mustPolicy(t *testing.T, name, doc string) Policy {
	t.Helper()
	var p Policy
	if err := json.Unmarshal([]byte(doc), &p); err != nil {
		t.Fatal(err)
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	p.Name = name
	return p
}

func TestWildcard(t *testing.T) {
	cases := []struct {
		p, s string
		want bool
	}{
		{"*", "anything", true},
		{"s3:Get*", "s3:GetObject", true},
		{"s3:Get*", "s3:PutObject", false},
		{"arn:aws:s3:::prod-*/*", "arn:aws:s3:::prod-customers/2024/x.csv", true},
		{"arn:aws:s3:::prod-*/*", "arn:aws:s3:::dev-customers/x", false},
		{"iam:?etRole", "iam:GetRole", true},
		{"iam:?etRole", "iam:GGetRole", false},
		{"a*b*c", "aXXbYYc", true},
		{"a*b*c", "aXXbYY", false},
		{"", "", true},
	}
	for _, c := range cases {
		if got := Wildcard(c.p, c.s); got != c.want {
			t.Errorf("Wildcard(%q,%q)=%v want %v", c.p, c.s, got, c.want)
		}
	}
}

func TestExplicitDenyBeatsAllow(t *testing.T) {
	admin := mustPolicy(t, "Admin", `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`)
	guard := mustPolicy(t, "ProtectAudit", `{"Version":"2012-10-17","Statement":[{"Sid":"NoTrailTampering","Effect":"Deny",
		"Action":["cloudtrail:StopLogging","cloudtrail:DeleteTrail"],"Resource":"*"}]}`)
	d := Evaluate([]Policy{admin, guard}, Request{Action: "cloudtrail:StopLogging", Resource: "arn:aws:cloudtrail:eu-central-1:1:trail/org"})
	if d.Allowed || d.Reason != "explicit deny by ProtectAudit/NoTrailTampering" {
		t.Fatalf("got %+v", d)
	}
	if d := Evaluate([]Policy{admin, guard}, Request{Action: "s3:GetObject", Resource: "arn:aws:s3:::x/y"}); !d.Allowed {
		t.Fatalf("admin should still read: %+v", d)
	}
}

func TestImplicitDenyAndCaseRules(t *testing.T) {
	p := mustPolicy(t, "Read", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"S3:GETOBJECT","Resource":"arn:aws:s3:::prod-data/*"}]}`)
	if !Evaluate([]Policy{p}, Request{Action: "s3:GetObject", Resource: "arn:aws:s3:::prod-data/a"}).Allowed {
		t.Fatal("actions are case-insensitive")
	}
	if Evaluate([]Policy{p}, Request{Action: "s3:GetObject", Resource: "arn:aws:s3:::PROD-DATA/a"}).Allowed {
		t.Fatal("resources are case-sensitive")
	}
	if d := Evaluate([]Policy{p}, Request{Action: "s3:PutObject", Resource: "arn:aws:s3:::prod-data/a"}); d.Allowed || d.Reason != "implicit deny" {
		t.Fatalf("got %+v", d)
	}
}

func TestNotActionAndNotResource(t *testing.T) {
	// the classic "everything except IAM" developer policy
	p := mustPolicy(t, "PowerUser", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","NotAction":["iam:*","organizations:*"],"Resource":"*"}]}`)
	if Evaluate([]Policy{p}, Request{Action: "iam:CreateAccessKey", Resource: "*"}).Allowed {
		t.Fatal("NotAction must exclude iam:*")
	}
	if !Evaluate([]Policy{p}, Request{Action: "rds-db:connect", Resource: "arn:aws:rds-db:eu-central-1:1:dbuser:prod/app"}).Allowed {
		t.Fatal("everything else is allowed")
	}
	q := mustPolicy(t, "AllButProd", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","NotResource":["arn:aws:s3:::prod-*","arn:aws:s3:::prod-*/*"]}]}`)
	if Evaluate([]Policy{q}, Request{Action: "s3:GetObject", Resource: "arn:aws:s3:::prod-customers/x"}).Allowed {
		t.Fatal("NotResource must exclude prod")
	}
}

func TestMFACondition(t *testing.T) {
	// admin only with MFA: without MFA in context the Allow does not apply
	p := mustPolicy(t, "AdminWithMFA", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*",
		"Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}}]}`)
	req := Request{Action: "iam:AttachUserPolicy", Resource: "*"}
	if Evaluate([]Policy{p}, req).Allowed {
		t.Fatal("missing key must not satisfy Bool")
	}
	req.Context = map[string]string{"aws:MultiFactorAuthPresent": "true"}
	if !Evaluate([]Policy{p}, req).Allowed {
		t.Fatal("MFA present should allow")
	}
	// the AWS-recommended deny: BoolIfExists false denies long-term keys too (key absent → IfExists true)
	deny := mustPolicy(t, "DenyWithoutMFA", `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","NotAction":"iam:ChangePassword","Resource":"*",
		"Condition":{"BoolIfExists":{"aws:MultiFactorAuthPresent":"false"}}}]}`)
	all := mustPolicy(t, "Admin", `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`)
	if Evaluate([]Policy{all, deny}, Request{Action: "s3:GetObject", Resource: "*"}).Allowed {
		t.Fatal("absent MFA key with BoolIfExists false must deny")
	}
	if !Evaluate([]Policy{all, deny}, Request{Action: "s3:GetObject", Resource: "*", Context: map[string]string{"aws:multifactorauthpresent": "true"}}).Allowed {
		t.Fatal("condition keys are case-insensitive")
	}
}

func TestIPAndNumericAndUnknownOperator(t *testing.T) {
	p := mustPolicy(t, "Office", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*",
		"Condition":{"IpAddress":{"aws:SourceIp":["203.0.113.0/24","198.51.100.7"]},"NumericLessThan":{"s3:max-keys":"100"}}}]}`)
	ok := map[string]string{"aws:SourceIp": "203.0.113.9", "s3:max-keys": "10"}
	if !Evaluate([]Policy{p}, Request{Action: "s3:ListBucket", Resource: "*", Context: ok}).Allowed {
		t.Fatal("in range")
	}
	if Evaluate([]Policy{p}, Request{Action: "s3:ListBucket", Resource: "*", Context: map[string]string{"aws:SourceIp": "192.0.2.1", "s3:max-keys": "10"}}).Allowed {
		t.Fatal("outside the office range")
	}
	if Evaluate([]Policy{p}, Request{Action: "s3:ListBucket", Resource: "*", Context: map[string]string{"aws:SourceIp": "203.0.113.9", "s3:max-keys": "500"}}).Allowed {
		t.Fatal("conditions are ANDed")
	}
	u := mustPolicy(t, "Weird", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:CurrentTime":"2030-01-01T00:00:00Z"}}}]}`)
	if Evaluate([]Policy{u}, Request{Action: "s3:GetObject", Resource: "*", Context: map[string]string{"aws:CurrentTime": "2026-01-01T00:00:00Z"}}).Allowed {
		t.Fatal("unsupported operator must fail closed for Allow")
	}
}

func TestValidate(t *testing.T) {
	var p Policy
	if err := json.Unmarshal([]byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","NotAction":"iam:*","Resource":"*"}]}`), &p); err != nil {
		t.Fatal(err)
	}
	if p.Validate() == nil {
		t.Fatal("Action and NotAction together must be rejected")
	}
}

func FuzzWildcardNoPanic(f *testing.F) {
	f.Add("a*b?c", "aXXbYc")
	f.Fuzz(func(t *testing.T, p, s string) {
		first := Wildcard(p, s)
		if second := Wildcard(p, s); first != second {
			t.Fatal("non-deterministic")
		}
		if !Wildcard("*", s) {
			t.Fatal("* must match everything")
		}
	})
}
