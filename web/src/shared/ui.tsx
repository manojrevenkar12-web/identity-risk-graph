import type { CSSProperties, ReactNode } from "react";
import { color, font, leading, measure, radius, size, space, stroke, weight } from "../app/theme";

export function Section({ title, note, children }: { title: string; note?: string; children: ReactNode }) {
  return (
    <section aria-label={title} style={{ marginBottom: space[7] }}>
      <h2 style={{ fontSize: size.md, fontWeight: weight.bold, lineHeight: leading.tight, margin: 0 }}>{title}</h2>
      {note && <p style={{ color: color.inkSoft, fontSize: size.sm, margin: `${space[1]} 0 ${space[4]}`, maxWidth: measure.prose }}>{note}</p>}
      {children}
    </section>
  );
}

const box: CSSProperties = { background: color.sheet, border: `${stroke.rule} solid ${color.rule}`, borderRadius: radius.m, padding: space[5], fontSize: size.sm };

export function Skeleton({ rows }: { rows: number }) {
  return (
    <div role="status" aria-label="Loading">
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} style={{ height: space[7], background: color.pathSoft, borderRadius: radius.m, marginBottom: space[2] }} />
      ))}
    </div>
  );
}

export function ErrorState({ message, onRetry }: { message: string; onRetry: () => void }) {
  return (
    <div role="alert" style={{ ...box, borderColor: color.critical }}>
      <p style={{ margin: `0 0 ${space[3]}` }}>{message}</p>
      <button type="button" onClick={onRetry} style={button}>Try again</button>
    </div>
  );
}

export function EmptyState({ children }: { children: ReactNode }) {
  return <div style={{ ...box, color: color.inkSoft }}>{children}</div>;
}

export function Id({ children }: { children: ReactNode }) {
  return <span style={{ fontFamily: font.id, fontSize: size.sm }}>{children}</span>;
}

export const button: CSSProperties = {
  fontFamily: font.body, fontWeight: weight.medium, fontSize: size.sm, padding: `${space[2]} ${space[4]}`,
  background: color.ink, color: color.sheet, border: "none", borderRadius: radius.s, cursor: "pointer",
};
