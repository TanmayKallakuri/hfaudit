import { Badge } from "@/components/ui/badge";

export default function FindingsPage() {
  return (
    <div className="space-y-8">
      <section>
        <h1 className="font-mono text-3xl font-bold tracking-tight">
          Published Findings
        </h1>
        <p className="mt-2 max-w-2xl text-muted-foreground">
          Disclosed findings from HFAudit security scans. Only findings past
          their coordinated disclosure window appear here.
        </p>
      </section>

      <div className="rounded-lg border border-border p-8 text-center">
        <p className="font-mono text-lg text-muted-foreground">
          No published findings yet
        </p>
        <p className="mt-2 text-sm text-muted-foreground">
          Findings will appear here after their 90-day disclosure window closes.
          See our{" "}
          <Badge variant="outline" className="font-mono text-xs">
            disclosure policy
          </Badge>{" "}
          for details.
        </p>
      </div>
    </div>
  );
}
