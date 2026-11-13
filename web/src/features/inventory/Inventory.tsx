import { color, size, space, stroke, weight } from "../../app/theme";

const ORDER: [string, string][] = [["human", "People"], ["service_account", "Service accounts"], ["ai_agent", "AI agents"], ["oauth_app", "OAuth apps"]];

export function Inventory({ identities }: { identities: Record<string, number> }) {
  const fmt = new Intl.NumberFormat("en-GB");
  return (
    <div className="inv" style={{ gap: space[2] }}>
      {ORDER.map(([k, label]) => (
        <div key={k} style={{ borderTop: `${stroke.mark} solid ${k === "ai_agent" ? color.ink : color.rule}`, paddingTop: space[2] }}>
          <div style={{ fontSize: size.lg, fontWeight: weight.bold, fontVariantNumeric: "tabular-nums" }}>{fmt.format(identities[k] ?? 0)}</div>
          <div style={{ fontSize: size.xs, color: color.inkSoft }}>{label}</div>
        </div>
      ))}
    </div>
  );
}
