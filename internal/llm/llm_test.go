package llm

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/manojrevenkar12-web/identity-risk-graph/internal/model"
)

// The worked example from AWS's documentation ("Create a signed AWS API request": IAM ListUsers).
func TestSigV4MatchesAWSExample(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	SignV4(req, nil, Credentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"}, "us-east-1", "iam",
		time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC))
	want := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, " +
		"Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
	if got := req.Header.Get("Authorization"); got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestCanonicalURIDoubleEncodesForBedrock(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "https://bedrock-runtime.eu-central-1.amazonaws.com/model/anthropic.claude-sonnet%3A0/converse", nil)
	if got := canonicalURI(req.URL, "bedrock"); got != "/model/anthropic.claude-sonnet%253A0/converse" {
		t.Fatal(got)
	}
}

func finding() model.Finding {
	return model.Finding{Title: "svc-1 can change production data and erase the audit trail", Rule: "toxic_combination", Severity: model.Critical, Score: 100,
		Evidence: []string{"svc-1 → role:InfraAdmin → tamper org-trail"}, BlastRadius: 7, Controls: []string{"SOC2 CC7.2"},
		Remediation: []model.Action{{Type: "unassign_role", Target: "svc-1", From: "role:CIRunner"}}}
}

func TestBedrockConverseAndFallback(t *testing.T) {
	var gotPath, gotAuth, gotRaw string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth = r.URL.EscapedPath(), r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotRaw = string(b) + fmt.Sprint(r.Header)
		_, _ = w.Write([]byte(`{"output":{"message":{"role":"assistant","content":[{"text":"  CI can wipe the trail.  "}]}}}`))
	}))
	defer srv.Close()
	b := &Bedrock{Region: "eu-central-1", ModelID: "anthropic.claude-sonnet:0", Creds: Credentials{AccessKeyID: "AKID", SecretAccessKey: "SECRET-never-on-the-wire"}, Endpoint: srv.URL, Fallback: Template{}}
	text, src, err := b.Explain(context.Background(), finding())
	if err != nil || text != "CI can wipe the trail." || src != "bedrock:anthropic.claude-sonnet:0" {
		t.Fatalf("%q %q %v", text, src, err)
	}
	if gotPath != "/model/anthropic.claude-sonnet%3A0/converse" || !strings.HasPrefix(gotAuth, "AWS4-HMAC-SHA256 Credential=AKID/") || !strings.Contains(gotAuth, "/eu-central-1/bedrock/aws4_request") {
		t.Fatalf("path %s auth %s", gotPath, gotAuth)
	}
	if strings.Contains(gotRaw, "SECRET-never-on-the-wire") {
		t.Fatal("the secret key must never be sent")
	}
	srv.Close() // Bedrock down: the template answers and says so
	text, src, err = b.Explain(context.Background(), finding())
	if err != nil || !strings.HasPrefix(src, "template (bedrock unavailable") || !strings.Contains(text, "Suggested fix: unassign role svc-1") {
		t.Fatalf("%q %q %v", text, src, err)
	}
}
