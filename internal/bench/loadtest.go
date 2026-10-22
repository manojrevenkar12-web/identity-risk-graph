package bench

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// LoadTest drives POST /v1/agents/decide over HTTP with `concurrency` closed-loop clients for
// `d`, one agent key per client (so per-key rate limits do not distort the result), and reports
// throughput and latency percentiles including HTTP, authentication and JSON.
func LoadTest(base string, keys map[string]string, concurrency int, d time.Duration) (map[string]any, error) {
	type kv struct{ agent, key string }
	var pairs []kv
	for a, k := range keys {
		pairs = append(pairs, kv{a, k})
	}
	if len(pairs) == 0 {
		return nil, fmt.Errorf("no agent keys")
	}
	tr := &http.Transport{MaxIdleConns: concurrency * 2, MaxIdleConnsPerHost: concurrency * 2}
	hc := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	var mu sync.Mutex
	var lat []float64
	var errs, n atomic.Int64
	outcomes := map[string]int{}
	stop := time.Now().Add(d)
	var wg sync.WaitGroup
	t0 := time.Now()
	for c := 0; c < concurrency; c++ {
		wg.Add(1)
		go func(c int) {
			defer wg.Done()
			p := pairs[c%len(pairs)]
			local := make([]float64, 0, 4096)
			out := map[string]int{}
			for i := 0; time.Now().Before(stop); i++ {
				body, _ := json.Marshal(map[string]string{"agent_id": p.agent, "action": []string{"s3:GetObject", "s3:PutObject", "rds-db:connect"}[i%3],
					"resource": []string{fmt.Sprintf("arn:aws:s3:::analytics-raw/part-%d", i), "arn:aws:s3:::analytics-raw/x", "arn:aws:rds-db:eu-central-1:111122223333:dbuser:staging-core/app"}[i%3]})
				req, _ := http.NewRequest(http.MethodPost, base+"/v1/agents/decide", bytes.NewReader(body))
				req.Header.Set("Authorization", "Bearer "+p.key)
				// a decision is a read: marking it idempotent lets the client replay it if a server
				// closes a keep-alive connection mid-rollout (Go retries only idempotent requests)
				req.Header.Set("Idempotency-Key", fmt.Sprintf("%d-%d", c, i))
				s := time.Now()
				resp, err := hc.Do(req)
				if err != nil {
					errs.Add(1)
					continue
				}
				var dec struct {
					Decision string `json:"decision"`
				}
				raw, _ := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				local = append(local, float64(time.Since(s).Microseconds())/1000)
				n.Add(1)
				if resp.StatusCode != 200 {
					errs.Add(1)
					out[fmt.Sprint("http_", resp.StatusCode)]++
					continue
				}
				_ = json.Unmarshal(raw, &dec)
				out[dec.Decision]++
			}
			mu.Lock()
			lat = append(lat, local...)
			for k, v := range out {
				outcomes[k] += v
			}
			mu.Unlock()
		}(c)
	}
	wg.Wait()
	el := time.Since(t0)
	sort.Float64s(lat)
	pct := func(p float64) float64 {
		if len(lat) == 0 {
			return 0
		}
		return round(lat[int(p*float64(len(lat)-1))])
	}
	return map[string]any{"concurrency": concurrency, "seconds": round(el.Seconds()), "requests": n.Load(), "errors": errs.Load(),
		"requests_per_second": int(float64(n.Load()) / el.Seconds()), "latency_ms": map[string]float64{"p50": pct(.5), "p95": pct(.95), "p99": pct(.99), "max": pct(1)},
		"outcomes": outcomes}, nil
}
