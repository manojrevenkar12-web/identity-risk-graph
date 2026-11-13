//go:build collector

package trace

import (
	"bufio"
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// Run against a real OpenTelemetry Collector (CI job "otel"): the collector must accept every span
// and write it out unchanged. IRG_OTLP_ENDPOINT is its OTLP/HTTP address, IRG_COLLECTOR_OUT its file.
func TestARealCollectorAcceptsOurSpans(t *testing.T) {
	tr := New(Config{Service: "irg-collector-test", Version: "ci", Endpoint: os.Getenv("IRG_OTLP_ENDPOINT"), Ratio: 1})
	var want []string
	for i := 0; i < 50; i++ {
		ctx, s := tr.Start(context.Background(), "POST /v1/agents/decide", Server, String("http.route", "/v1/agents/decide"))
		_, c := tr.Start(ctx, "pdp.decide", Internal, Int("i", i), Bool("crown", i%2 == 0), Float("f", 0.5))
		c.End()
		s.End()
		want = append(want, s.TraceID())
	}
	if err := tr.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if exported, dropped, failed := tr.Stats(); exported != 100 || dropped != 0 || failed != 0 {
		t.Fatalf("exported %d dropped %d failed %d", exported, dropped, failed)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		f, err := os.Open(os.Getenv("IRG_COLLECTOR_OUT"))
		if err == nil {
			var all strings.Builder
			sc := bufio.NewScanner(f)
			sc.Buffer(make([]byte, 1<<20), 64<<20)
			for sc.Scan() {
				all.WriteString(sc.Text())
			}
			_ = f.Close()
			missing := 0
			for _, id := range want {
				if !strings.Contains(all.String(), id) {
					missing++
				}
			}
			if missing == 0 {
				t.Logf("the collector wrote all %d traces", len(want))
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("%d of %d traces missing from the collector's output", missing, len(want))
			}
		} else if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(time.Second)
	}
}
