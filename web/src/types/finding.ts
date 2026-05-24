export type Severity = "critical" | "high" | "medium" | "low" | "informational";

export interface Finding {
  id: string;
  model_id: string;
  severity: Severity;
  rule_id: string;
  category: string;
  description: string;
  evidence: string;
  file_path: string;
  confidence: number;
  references: string[];
  false_positive_notes: string;
  bypass_notes: string;
  disclosure_status: "internal" | "reported" | "acknowledged" | "fixed" | "published";
  disclosure_id: string | null;
  published_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface ScanStat {
  id: string;
  stat_date: string;
  total_scanned: number;
  findings_critical: number;
  findings_high: number;
  findings_medium: number;
  findings_low: number;
  findings_informational: number;
  active_disclosures: number;
  created_at: string;
}

export interface Rule {
  id: string;
  severity: Severity;
  category: string;
  description: string;
  references: string[];
  false_positive_notes: string;
  bypass_notes: string;
  active: boolean;
  created_at: string;
  updated_at: string;
}
