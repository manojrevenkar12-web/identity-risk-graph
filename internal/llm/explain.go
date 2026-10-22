package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/manojrevenkar12-web/identity-risk-graph/internal/model"
)

type Explainer interface {
	Explain(ctx context.Context, f model.Finding) (text string, source string, err error)
}

// Template is the deterministic explainer: always available, never wrong about the facts.
type Template struct{}

func (Template) Explain(_ context.Context, f model.Finding) (string, string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "%s. Severity %s (score %.0f)", f.Title, f.Severity, f.Score)
	if f.BlastRadius > 0 {
		fmt.Fprintf(&b, "; %d crown-jewel resources are exposed", f.BlastRadius)
	}
	b.WriteString(".\nWhy: " + strings.Join(f.Evidence, "; ") + ".")
	if len(f.Remediation) > 0 {
		var acts []string
		for _, a := range f.Remediation {
			acts = append(acts, strings.ReplaceAll(a.Type, "_", " ")+" "+a.Target)
		}
		b.WriteString("\nSuggested fix: " + strings.Join(acts, "; ") + " (reversible, through a reviewed plan).")
	}
	b.WriteString("\nControls: " + strings.Join(f.Controls, ", ") + ".")
	return b.String(), "template", nil
}

// Bedrock calls the Converse API of a model on Amazon Bedrock, signed with SigV4.
type Bedrock struct {
	Region, ModelID string
	Creds           Credentials
	Endpoint        string // override for tests; default https://bedrock-runtime.<region>.amazonaws.com
	HTTP            *http.Client
	Fallback        Explainer
}

const system = `You explain identity-security findings to a CISO in at most 120 words: what the risk is,
why it matters for this company, and what the suggested fix does. Use only the facts given. Do not
invent identities, resources or numbers. Do not tell the reader to take actions outside the
suggested fix.`

func (b *Bedrock) Explain(ctx context.Context, f model.Finding) (string, string, error) {
	text, err := b.converse(ctx, f)
	if err != nil {
		if b.Fallback != nil {
			t, src, ferr := b.Fallback.Explain(ctx, f)
			return t, src + " (bedrock unavailable: " + err.Error() + ")", ferr
		}
		return "", "", err
	}
	return text, "bedrock:" + b.ModelID, nil
}

func (b *Bedrock) converse(ctx context.Context, f model.Finding) (string, error) {
	facts, _ := json.Marshal(map[string]any{"title": f.Title, "rule": f.Rule, "severity": f.Severity, "evidence": f.Evidence, "blast_radius": f.BlastRadius,
		"controls": f.Controls, "suggested_fix": f.Remediation})
	body, _ := json.Marshal(map[string]any{
		"system":          []map[string]string{{"text": system}},
		"messages":        []map[string]any{{"role": "user", "content": []map[string]string{{"text": "Finding:\n" + string(facts)}}}},
		"inferenceConfig": map[string]any{"maxTokens": 300, "temperature": 0.2},
	})
	endpoint := b.Endpoint
	if endpoint == "" {
		endpoint = "https://bedrock-runtime." + b.Region + ".amazonaws.com"
	}
	u := endpoint + "/model/" + uriEncode(b.ModelID) + "/converse" // ":" in model IDs must be %3A, as the AWS SDKs send it
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	SignV4(req, body, b.Creds, b.Region, "bedrock", time.Now())
	hc := b.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 20 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("bedrock HTTP %d: %s", resp.StatusCode, truncate(string(raw), 200))
	}
	var out struct {
		Output struct {
			Message struct {
				Content []struct {
					Text string `json:"text"`
				} `json:"content"`
			} `json:"message"`
		} `json:"output"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || len(out.Output.Message.Content) == 0 {
		return "", fmt.Errorf("bedrock: unexpected response")
	}
	return strings.TrimSpace(out.Output.Message.Content[0].Text), nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
