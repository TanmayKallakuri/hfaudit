import Link from "next/link";
import { notFound } from "next/navigation";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { SeverityBadge } from "@/components/severity-badge";
import { getFindingById } from "@/lib/queries";

interface FindingPageProps {
  params: Promise<{ id: string }>;
}

export default async function FindingPage({ params }: FindingPageProps) {
  const { id } = await params;

  if (!id.startsWith("HFA-")) {
    notFound();
  }

  const finding = await getFindingById(id);

  if (!finding) {
    notFound();
  }

  const publishedDate = finding.published_at
    ? new Date(finding.published_at).toLocaleDateString("en-US", {
        year: "numeric",
        month: "long",
        day: "numeric",
      })
    : null;

  const createdDate = new Date(finding.created_at).toLocaleDateString("en-US", {
    year: "numeric",
    month: "long",
    day: "numeric",
  });

  return (
    <div className="space-y-8">
      <section>
        <Link
          href="/findings"
          className="text-sm text-muted-foreground transition-colors hover:text-foreground"
        >
          &larr; All Findings
        </Link>
        <div className="mt-4 flex items-center gap-3">
          <h1 className="font-mono text-3xl font-bold tracking-tight">
            {finding.id}
          </h1>
          <SeverityBadge severity={finding.severity} />
        </div>
        <p className="mt-1 text-sm font-mono text-muted-foreground">
          {finding.category}
        </p>
      </section>

      <section className="grid gap-6 lg:grid-cols-3">
        <div className="space-y-6 lg:col-span-2">
          <Card>
            <CardHeader>
              <CardTitle className="font-mono text-base">Description</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-muted-foreground leading-relaxed">
                {finding.description}
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="font-mono text-base">Evidence</CardTitle>
            </CardHeader>
            <CardContent>
              <pre className="max-h-96 overflow-auto rounded bg-muted p-4 font-mono text-xs leading-relaxed">
                {finding.evidence}
              </pre>
            </CardContent>
          </Card>

          {finding.false_positive_notes && (
            <Card>
              <CardHeader>
                <CardTitle className="font-mono text-base">
                  False Positive Conditions
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground">
                  {finding.false_positive_notes}
                </p>
              </CardContent>
            </Card>
          )}

          {finding.bypass_notes && (
            <Card>
              <CardHeader>
                <CardTitle className="font-mono text-base">
                  Known Bypass Techniques
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground">
                  {finding.bypass_notes}
                </p>
              </CardContent>
            </Card>
          )}
        </div>

        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="font-mono text-base">Details</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <div>
                <p className="text-xs text-muted-foreground">Model</p>
                <code className="font-mono text-sm">{finding.model_id}</code>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">File</p>
                <code className="font-mono text-sm">{finding.file_path}</code>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Rule</p>
                <code className="font-mono text-sm">{finding.rule_id}</code>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Confidence</p>
                <span className="font-mono text-sm">
                  {(finding.confidence * 100).toFixed(0)}%
                </span>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="font-mono text-base">Timeline</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <div>
                <p className="text-xs text-muted-foreground">Detected</p>
                <span className="text-sm">{createdDate}</span>
              </div>
              {publishedDate && (
                <div>
                  <p className="text-xs text-muted-foreground">Published</p>
                  <span className="text-sm">{publishedDate}</span>
                </div>
              )}
            </CardContent>
          </Card>

          {finding.references.filter((ref) => ref.startsWith("https://") || ref.startsWith("http://")).length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="font-mono text-base">
                  References
                </CardTitle>
              </CardHeader>
              <CardContent>
                <ul className="space-y-2">
                  {finding.references
                    .filter((ref) => ref.startsWith("https://") || ref.startsWith("http://"))
                    .map((ref, i) => (
                    <li key={`${ref}-${i}`}>
                      <a
                        href={ref}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="break-all font-mono text-xs text-muted-foreground transition-colors hover:text-foreground"
                      >
                        {ref}
                      </a>
                    </li>
                  ))}
                </ul>
              </CardContent>
            </Card>
          )}
        </div>
      </section>
    </div>
  );
}
