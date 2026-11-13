import type { Dashboard } from "../../shared/types";
import { EmptyState } from "../../shared/ui";
import { color, size, space, stroke, weight } from "../../app/theme";

function Row({ value, label }: { value: string; label: string }) {
  return (
    <div style={{ borderTop: `${stroke.rule} solid ${color.rule}`, padding: `${space[3]} 0` }}>
      <div style={{ fontSize: size.md, fontWeight: weight.bold, fontVariantNumeric: "tabular-nums" }}>{value}</div>
      <div style={{ fontSize: size.sm, color: color.inkSoft }}>{label}</div>
    </div>
  );
}

export function Trust({ d }: { d: Dashboard }) {
  const fmt = new Intl.NumberFormat("en-GB");
  if (!d.detection && !d.decisions && !d.siem) return <EmptyState>Run irg bench and irg siem-drill to fill this in.</EmptyState>;
  return (
    <div>
      {d.detection && (
        <Row value={`${d.detection.graph_engine.precision.toFixed(2)} vs ${d.detection.naive_scanner.precision.toFixed(2)}`}
          label={`precision against planted risks, graph engine vs a configuration scanner (${fmt.format(d.detection.naive_scanner.false_positives)} false alarms avoided)`} />
      )}
      {d.decisions && (
        <Row value={`${d.decisions.latency_us.p99.toFixed(1)} µs`} label="p99 for an AI agent's question, inside the engine" />
      )}
      {d.siem && (
        <Row value={`${d.siem.events_missing} of ${fmt.format(d.siem.events_expected)}`}
          label={`security events missing at the SIEM after ${d.siem.busy_replies} busy replies and ${d.siem.lost_acknowledgements} lost acknowledgements (${d.siem.duplicate_deliveries} duplicates, each with a stable id)`} />
      )}
    </div>
  );
}
