import { useQuery } from "@tanstack/react-query";
import { motion, useReducedMotion } from "framer-motion";
import { fetchDashboard } from "../shared/api";
import { ErrorState, Section, Skeleton } from "../shared/ui";
import { RiskList } from "../features/risks/RiskList";
import { RuleLedger } from "../features/ledger/RuleLedger";
import { Inventory } from "../features/inventory/Inventory";
import { Trust } from "../features/evidence/Trust";
import { color, font, leading, measure, motion as m, size, space, weight } from "./theme";

export function App() {
  const q = useQuery({ queryKey: ["dashboard"], queryFn: fetchDashboard });
  const reduce = useReducedMotion();
  const d = q.data;
  const critical = d?.open.critical ?? 0;
  const total = d ? Object.values(d.open).reduce((a, b) => a + b, 0) : 0;
  return (
    <div style={{ fontFamily: font.body, lineHeight: leading.body, color: color.ink }}>
      <main style={{ maxWidth: measure.page, margin: "0 auto", padding: `${space[6]} ${space[5]}` }}>
        <header style={{ marginBottom: space[6] }}>
          <p style={{ margin: 0, color: color.inkSoft, fontSize: size.sm }}>Identity risk{d ? ` · synthetic company of ${new Intl.NumberFormat("en-GB").format(d.company.humans)} people` : ""}</p>
          <h1 style={{ fontSize: size.xl, fontWeight: weight.bold, lineHeight: leading.tight, margin: `${space[2]} 0 0`, maxWidth: measure.prose }}>
            {d ? (
              <motion.span initial={reduce ? false : { opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: m.open }}>
                {critical} of {total} open identity risks are critical: who can change production, erase the audit trail or grant themselves more.
              </motion.span>
            ) : "Which identities can reach production, and how."}
          </h1>
        </header>
        {q.isPending && <Skeleton rows={8} />}
        {q.isError && <ErrorState message={(q.error as Error).message} onRetry={() => q.refetch()} />}
        {d && (
          <div className="cols" style={{ gap: space[6] }}>
            <div>
              <Section title="Highest risks" note="Ranked by severity and by how many crown-jewel resources the identity can reach. Open one to see the path, the controls it breaks and the fix.">
                <RiskList risks={d.top} />
              </Section>
            </div>
            <div>
              <Section title="Identities">
                <Inventory identities={d.company.identities} />
              </Section>
              <Section title="By risk" note="Mapped to SOC 2 and ISO 27001 controls.">
                <RuleLedger rules={d.rules} />
              </Section>
              <Section title="Why these numbers hold">
                <Trust d={d} />
              </Section>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
