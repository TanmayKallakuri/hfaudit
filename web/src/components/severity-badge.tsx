import { Badge } from "@/components/ui/badge";
import type { Severity } from "@/types/finding";

const severityStyles: Record<Severity, string> = {
  critical: "border-red-500/30 text-red-400 bg-red-500/10",
  high: "border-orange-500/30 text-orange-400 bg-orange-500/10",
  medium: "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
  low: "border-blue-500/30 text-blue-400 bg-blue-500/10",
  informational: "border-border text-muted-foreground",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <Badge variant="outline" className={`font-mono text-xs ${severityStyles[severity]}`}>
      {severity}
    </Badge>
  );
}
