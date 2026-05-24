import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { SeverityBadge } from "@/components/severity-badge";
import type { Rule } from "@/types/finding";

export function RuleCard({ rule }: { rule: Rule }) {
  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="font-mono text-base">{rule.id}</CardTitle>
          <SeverityBadge severity={rule.severity} />
        </div>
        <p className="text-xs font-mono text-muted-foreground">
          {rule.category}
        </p>
      </CardHeader>
      <CardContent className="space-y-3">
        <p className="text-sm text-muted-foreground">{rule.description}</p>

        {rule.false_positive_notes && (
          <div>
            <p className="text-xs font-medium text-muted-foreground">
              False Positive Conditions
            </p>
            <p className="mt-1 text-xs text-muted-foreground/80">
              {rule.false_positive_notes}
            </p>
          </div>
        )}

        {rule.bypass_notes && (
          <div>
            <p className="text-xs font-medium text-muted-foreground">
              Known Bypass Techniques
            </p>
            <p className="mt-1 text-xs text-muted-foreground/80">
              {rule.bypass_notes}
            </p>
          </div>
        )}

        {rule.references.length > 0 && (
          <div className="flex flex-wrap gap-2">
            {rule.references
              .filter((ref) => ref.startsWith("https://") || ref.startsWith("http://"))
              .map((ref) => (
              <a
                key={ref}
                href={ref}
                target="_blank"
                rel="noopener noreferrer"
                className="rounded bg-muted px-2 py-0.5 font-mono text-xs text-muted-foreground transition-colors hover:text-foreground"
              >
                {ref}
              </a>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
