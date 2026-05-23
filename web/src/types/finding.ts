export interface Finding {
  id: string;
  model_id: string;
  severity: "critical" | "high" | "medium" | "low" | "informational";
  rule_id: string;
  category: string;
  description: string;
  evidence: string;
  file_path: string;
  confidence: number;
  references: string[];
  false_positive_notes: string;
  bypass_notes: string;
  timestamp: string;
}
