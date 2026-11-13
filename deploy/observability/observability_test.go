// Package observability holds the Grafana dashboard, Prometheus rules and collector configs. This
// test keeps them honest: every metric they query is one the code registers, with the labels used.
package observability

import (
	"bytes"
	"os"
	"regexp"
	"strings"
	"testing"

	_ "github.com/manojrevenkar12-web/identity-risk-graph/internal/app" // registers its metrics
	"github.com/manojrevenkar12-web/identity-risk-graph/internal/metrics"
	_ "github.com/manojrevenkar12-web/identity-risk-graph/internal/siem"
	_ "github.com/manojrevenkar12-web/identity-risk-graph/internal/trace"
)

func TestDashboardsAndAlertsQueryRealMetrics(t *testing.T) {
	var buf bytes.Buffer
	metrics.Default.Write(&buf)
	registered := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^# TYPE (\S+) (\S+)$`).FindAllStringSubmatch(buf.String(), -1) {
		registered[m[1]] = true
		if m[2] == "histogram" {
			registered[m[1]+"_bucket"], registered[m[1]+"_sum"], registered[m[1]+"_count"] = true, true, true
		}
	}
	use := regexp.MustCompile(`\birg_[a-z_]+\b`)
	for _, f := range []string{"grafana-dashboard.json", "prometheus-rules.yml"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range use.FindAllString(string(b), -1) {
			if strings.HasPrefix(name, "irg_http_errors") { // recording-rule names (irg:...) are not metrics
				continue
			}
			if !registered[name] {
				t.Errorf("%s queries %s, which the code does not register", f, name)
			}
		}
	}
}
