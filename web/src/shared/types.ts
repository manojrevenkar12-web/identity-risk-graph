export interface Rule { rule: string; title: string; open: number; critical: number; controls: string[] }
export interface Risk {
  id: string; title: string; severity: string; score: number; subject: string; kind: string;
  blast_radius: number; evidence: string[]; controls: string[]; fix: string[] | null;
}
export interface Dashboard {
  company: { humans: number; identities: Record<string, number>; edges: number };
  open: Record<string, number>;
  rules: Rule[];
  top: Risk[];
  detection: { graph_engine: { precision: number; recall: number; false_positives: number; true_positives: number };
               naive_scanner: { precision: number; recall: number; false_positives: number } } | null;
  decisions: { latency_us: Record<string, number>; single_core_per_second: number } | null;
  siem: { events_expected: number; events_missing: number; duplicate_deliveries: number; lost_acknowledgements: number;
          busy_replies: number; requests: number; events_from_other_tenants: number } | null;
}
