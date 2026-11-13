// Every colour, size, space and duration the dashboard uses. Components read these; they hold no raw values.
export const color = {
  paper: "#EEF1F4",
  sheet: "#FFFFFF",
  ink: "#16202B",
  inkSoft: "#566373",
  rule: "#D3D9E0",
  critical: "#C8102E", // the one loud colour: something an attacker could use today
  high: "#9A5B00",
  medium: "#4F6B86",
  low: "#7B8794",
  path: "#16202B",
  pathSoft: "#E3E8EE",
  ok: "#1F7A4D",
  focus: "#1D4ED8",
} as const;

export const font = {
  body: "'IBM Plex Sans', system-ui, sans-serif",
  id: "'IBM Plex Mono', ui-monospace, monospace", // identifiers: roles, ARNs, ids
} as const;

export const size = { xs: "0.75rem", sm: "0.875rem", base: "1rem", md: "1.25rem", lg: "1.6rem", xl: "2.4rem" } as const;
export const weight = { regular: 400, medium: 500, bold: 600 } as const;
export const leading = { tight: 1.15, body: 1.55 } as const;
export const space = { 1: "4px", 2: "8px", 3: "12px", 4: "16px", 5: "24px", 6: "32px", 7: "48px" } as const;
export const radius = { s: "2px", m: "4px" } as const;
export const measure = { prose: "66ch", page: "1200px" } as const;
export const stroke = { rule: "1px", mark: "3px" } as const;

export const motion = {
  hop: 0.09, // seconds between path nodes as an attack path draws
  open: 0.24,
  ease: [0.22, 0.8, 0.2, 1] as [number, number, number, number],
} as const;

export const severityColor: Record<string, string> = {
  critical: color.critical, high: color.high, medium: color.medium, low: color.low,
};
