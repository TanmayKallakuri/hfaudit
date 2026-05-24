import Link from "next/link";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { SeverityBadge } from "@/components/severity-badge";
import type { Finding } from "@/types/finding";

export function FindingCard({ finding }: { finding: Finding }) {
  const publishedDate = finding.published_at
    ? new Date(finding.published_at).toLocaleDateString("en-US", {
        year: "numeric",
        month: "short",
        day: "numeric",
      })
    : null;

  return (
    <Link href={`/findings/${finding.id}`}>
      <Card className="transition-colors hover:bg-accent/50">
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="font-mono text-base">{finding.id}</CardTitle>
            <SeverityBadge severity={finding.severity} />
          </div>
          <p className="text-xs font-mono text-muted-foreground">
            {finding.category}
          </p>
        </CardHeader>
        <CardContent className="space-y-2">
          <p className="text-sm text-muted-foreground line-clamp-2">
            {finding.description}
          </p>
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <code className="rounded bg-muted px-1.5 py-0.5 font-mono">
              {finding.model_id}
            </code>
            {publishedDate && <span>{publishedDate}</span>}
          </div>
        </CardContent>
      </Card>
    </Link>
  );
}
