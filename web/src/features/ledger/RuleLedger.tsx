import type { Rule } from "../../shared/types";
import { EmptyState } from "../../shared/ui";
import { color, size, space, stroke, weight } from "../../app/theme";

export function RuleLedger({ rules }: { rules: Rule[] }) {
  if (rules.length === 0) return <EmptyState>No rule has an open finding.</EmptyState>;
  return (
    <table style={{ width: "100%", borderCollapse: "collapse", fontSize: size.sm }}>
      <thead>
        <tr style={{ textAlign: "left", color: color.inkSoft }}>
          <th style={{ fontWeight: weight.medium, padding: space[2] }}>Risk</th>
          <th style={{ fontWeight: weight.medium, padding: space[2], textAlign: "right" }}>Open</th>
          <th style={{ fontWeight: weight.medium, padding: space[2], textAlign: "right" }}>Critical</th>
        </tr>
      </thead>
      <tbody>
        {rules.map((r) => (
          <tr key={r.rule} style={{ borderTop: `${stroke.rule} solid ${color.rule}` }}>
            <td style={{ padding: space[2] }}>
              {r.title}
              <div style={{ fontSize: size.xs, color: color.inkSoft }}>{r.controls.join(" · ")}</div>
            </td>
            <td style={{ padding: space[2], textAlign: "right", fontVariantNumeric: "tabular-nums" }}>{r.open}</td>
            <td style={{ padding: space[2], textAlign: "right", fontVariantNumeric: "tabular-nums", color: r.critical ? color.critical : color.inkSoft, fontWeight: r.critical ? weight.bold : weight.regular }}>{r.critical}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
