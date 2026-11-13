import { motion, useReducedMotion } from "framer-motion";
import { color, font, motion as m, radius, size, space, stroke } from "../../app/theme";

// "svc-1 → role:CIRunner → role:InfraAdmin → delete prod-core (allowed by InfraAdmin/stmt0)"
export function parsePath(line: string): { hops: string[]; note: string } {
  const [chain, note = ""] = line.split(" (");
  return { hops: chain.split(" → ").map((h) => h.trim()).filter(Boolean), note: note.replace(/\)$/, "") };
}

export function AttackPath({ line }: { line: string }) {
  const reduce = useReducedMotion();
  const { hops, note } = parsePath(line);
  if (hops.length < 2) {
    return <p style={{ margin: `${space[1]} 0`, fontSize: size.sm }}>{line}</p>;
  }
  return (
    <div style={{ margin: `${space[2]} 0 ${space[3]}` }}>
      <ol aria-label="Path" style={{ listStyle: "none", padding: 0, margin: 0, display: "flex", flexWrap: "wrap", alignItems: "center", gap: space[1] }}>
        {hops.map((h, i) => {
          const last = i === hops.length - 1;
          return (
            <motion.li key={`${i}-${h}`} initial={reduce ? false : { opacity: 0, x: -6 }} animate={{ opacity: 1, x: 0 }}
              transition={{ delay: i * m.hop, duration: m.open, ease: m.ease }}
              style={{ display: "flex", alignItems: "center", gap: space[1] }}>
              <span style={{
                fontFamily: font.id, fontSize: size.xs, padding: `${space[1]} ${space[2]}`, borderRadius: radius.s,
                background: last ? color.critical : color.pathSoft, color: last ? color.sheet : color.path,
                border: `${stroke.rule} solid ${last ? color.critical : color.rule}`,
              }}>{h}</span>
              {!last && <span aria-hidden style={{ color: color.inkSoft }}>→</span>}
            </motion.li>
          );
        })}
      </ol>
      {note && <div style={{ fontSize: size.xs, color: color.inkSoft, marginTop: space[1] }}>{note}</div>}
    </div>
  );
}
