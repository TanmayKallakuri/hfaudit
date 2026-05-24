import Link from "next/link";
import { FindingCard } from "@/components/finding-card";
import { getPublishedFindings } from "@/lib/queries";

export default async function FindingsPage() {
  const findings = await getPublishedFindings();

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

      {findings.length > 0 ? (
        <div className="space-y-4">
          {findings.map((finding) => (
            <FindingCard key={finding.id} finding={finding} />
          ))}
        </div>
      ) : (
        <div className="rounded-lg border border-border p-8 text-center">
          <p className="font-mono text-lg text-muted-foreground">
            No published findings yet
          </p>
          <p className="mt-2 text-sm text-muted-foreground">
            Findings will appear here after their 90-day disclosure window
            closes. See our{" "}
            <Link
              href="/disclosure"
              className="underline underline-offset-4 transition-colors hover:text-foreground"
            >
              disclosure policy
            </Link>{" "}
            for details.
          </p>
        </div>
      )}
    </div>
  );
}
