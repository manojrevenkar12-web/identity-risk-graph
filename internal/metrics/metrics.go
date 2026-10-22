// Package metrics is a small Prometheus text-format registry: counters, gauges and histograms
// with labels. Enough for /metrics without pulling a dependency tree into a security product.
package metrics

import (
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"sync"
)

type Registry struct {
	mu     sync.Mutex
	order  []string
	series map[string]*family
}

type family struct {
	name, help, kind string
	labels           []string
	buckets          []float64
	values           map[string]*value // label values joined by \xff
}

type value struct {
	mu     sync.Mutex
	v      float64
	counts []uint64
	sum    float64
	n      uint64
}

var Default = NewRegistry()

func NewRegistry() *Registry { return &Registry{series: map[string]*family{}} }

func (r *Registry) register(name, help, kind string, labels []string, buckets []float64) *family {
	r.mu.Lock()
	defer r.mu.Unlock()
	if f, ok := r.series[name]; ok {
		return f
	}
	f := &family{name: name, help: help, kind: kind, labels: labels, buckets: buckets, values: map[string]*value{}}
	r.series[name] = f
	r.order = append(r.order, name)
	return f
}

func (r *Registry) get(f *family, lv []string) *value {
	if len(lv) != len(f.labels) {
		panic(fmt.Sprintf("metric %s: %d label values for %d labels", f.name, len(lv), len(f.labels)))
	}
	k := strings.Join(lv, "\xff")
	r.mu.Lock()
	defer r.mu.Unlock()
	v, ok := f.values[k]
	if !ok {
		v = &value{counts: make([]uint64, len(f.buckets))}
		f.values[k] = v
	}
	return v
}

type Counter struct {
	r *Registry
	f *family
}

func (r *Registry) Counter(name, help string, labels ...string) Counter {
	return Counter{r, r.register(name, help, "counter", labels, nil)}
}
func (c Counter) Add(n float64, lv ...string) {
	v := c.r.get(c.f, lv)
	v.mu.Lock()
	v.v += n
	v.mu.Unlock()
}
func (c Counter) Inc(lv ...string) { c.Add(1, lv...) }

type Gauge struct {
	r *Registry
	f *family
}

func (r *Registry) Gauge(name, help string, labels ...string) Gauge {
	return Gauge{r, r.register(name, help, "gauge", labels, nil)}
}
func (g Gauge) Set(n float64, lv ...string) {
	v := g.r.get(g.f, lv)
	v.mu.Lock()
	v.v = n
	v.mu.Unlock()
}

type Histogram struct {
	r *Registry
	f *family
}

func (r *Registry) Histogram(name, help string, buckets []float64, labels ...string) Histogram {
	return Histogram{r, r.register(name, help, "histogram", labels, buckets)}
}
func (h Histogram) Observe(x float64, lv ...string) {
	v := h.r.get(h.f, lv)
	v.mu.Lock()
	for i, b := range h.f.buckets {
		if x <= b {
			v.counts[i]++
		}
	}
	v.sum += x
	v.n++
	v.mu.Unlock()
}

// Write renders the registry in the Prometheus text exposition format.
func (r *Registry) Write(w io.Writer) {
	r.mu.Lock()
	names := append([]string{}, r.order...)
	r.mu.Unlock()
	for _, name := range names {
		f := r.series[name]
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", f.name, f.help, f.name, f.kind)
		r.mu.Lock()
		keys := make([]string, 0, len(f.values))
		for k := range f.values {
			keys = append(keys, k)
		}
		r.mu.Unlock()
		sort.Strings(keys)
		for _, k := range keys {
			r.mu.Lock()
			v := f.values[k]
			r.mu.Unlock()
			var lv []string
			if k != "" || len(f.labels) > 0 {
				lv = strings.Split(k, "\xff")
			}
			v.mu.Lock()
			switch f.kind {
			case "histogram":
				for i, b := range f.buckets {
					fmt.Fprintf(w, "%s_bucket%s %d\n", f.name, labels(f.labels, lv, "le", fmtFloat(b)), v.counts[i])
				}
				fmt.Fprintf(w, "%s_bucket%s %d\n%s_sum%s %s\n%s_count%s %d\n", f.name, labels(f.labels, lv, "le", "+Inf"), v.n,
					f.name, labels(f.labels, lv, "", ""), fmtFloat(v.sum), f.name, labels(f.labels, lv, "", ""), v.n)
			default:
				fmt.Fprintf(w, "%s%s %s\n", f.name, labels(f.labels, lv, "", ""), fmtFloat(v.v))
			}
			v.mu.Unlock()
		}
	}
}

func labels(names, values []string, extraK, extraV string) string {
	var parts []string
	for i, n := range names {
		parts = append(parts, fmt.Sprintf("%s=%q", n, values[i]))
	}
	if extraK != "" {
		parts = append(parts, fmt.Sprintf("%s=%q", extraK, extraV))
	}
	if len(parts) == 0 {
		return ""
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func fmtFloat(f float64) string {
	if math.IsInf(f, 1) {
		return "+Inf"
	}
	return fmt.Sprintf("%g", f)
}
