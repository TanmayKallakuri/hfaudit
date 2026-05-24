import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { StatsGrid } from "@/components/stats-grid";
import { getLatestStats, getRulesCount } from "@/lib/queries";

const coverageTiers = [
  {
    tier: 1,
    formats: "PyTorch (.pt, .pth, .bin, .ckpt)",
    depth: "Deep",
    status: "active" as const,
  },
  {
    tier: 1,
    formats: "TensorFlow SavedModel (.pb)",
    depth: "Deep",
    status: "active" as const,
  },
  {
    tier: 2,
    formats: "Keras (.h5, .keras)",
    depth: "Rigorous",
    status: "active" as const,
  },
  {
    tier: 3,
    formats: "ONNX, GGUF, safetensors",
    depth: "Light",
    status: "active" as const,
  },
];

export default async function Home() {
  const [latestStats, rulesCount] = await Promise.all([
    getLatestStats(),
    getRulesCount(),
  ]);

  const totalFindings = latestStats
    ? latestStats.findings_critical +
      latestStats.findings_high +
      latestStats.findings_medium +
      latestStats.findings_low +
      latestStats.findings_informational
    : 0;

  const stats = [
    {
      label: "Models Scanned",
      value: latestStats?.total_scanned ?? "—",
      description: latestStats
        ? `As of ${new Date(latestStats.stat_date).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" })}`
        : "Scanning begins soon",
    },
    {
      label: "Active Rules",
      value: rulesCount || "—",
      description: "Detection rules loaded",
    },
    {
      label: "Findings",
      value: latestStats ? totalFindings : "—",
      description: "Total findings detected",
    },
    {
      label: "Active Disclosures",
      value: latestStats?.active_disclosures ?? "0",
      description: "Under coordinated disclosure",
    },
  ];

  return (
    <div className="space-y-10">
      <section>
        <h1 className="font-mono text-3xl font-bold tracking-tight">
          HFAudit
        </h1>
        <p className="mt-2 max-w-2xl text-muted-foreground">
          Automated security scanning for HuggingFace model repositories.
          Multi-stage static and behavioral analysis with coordinated
          vulnerability disclosure.
        </p>
      </section>

      <StatsGrid stats={stats} />

      {latestStats && (latestStats.findings_critical > 0 || latestStats.findings_high > 0) && (
        <section>
          <h2 className="font-mono text-xl font-semibold">
            Findings by Severity
          </h2>
          <div className="mt-4 grid gap-3 sm:grid-cols-5">
            {([
              { label: "Critical", count: latestStats.findings_critical, color: "text-red-400" },
              { label: "High", count: latestStats.findings_high, color: "text-orange-400" },
              { label: "Medium", count: latestStats.findings_medium, color: "text-yellow-400" },
              { label: "Low", count: latestStats.findings_low, color: "text-blue-400" },
              { label: "Info", count: latestStats.findings_informational, color: "text-muted-foreground" },
            ] as const).map((item) => (
              <div
                key={item.label}
                className="flex flex-col items-center rounded-lg border border-border px-4 py-3"
              >
                <span className={`font-mono text-2xl font-bold ${item.color}`}>
                  {item.count}
                </span>
                <span className="text-xs text-muted-foreground">
                  {item.label}
                </span>
              </div>
            ))}
          </div>
        </section>
      )}

      <section>
        <h2 className="font-mono text-xl font-semibold">Format Coverage</h2>
        <div className="mt-4 grid gap-3">
          {coverageTiers.map((tier) => (
            <div
              key={tier.formats}
              className="flex items-center justify-between rounded-lg border border-border px-4 py-3"
            >
              <div className="flex items-center gap-4">
                <Badge variant="outline" className="font-mono">
                  Tier {tier.tier}
                </Badge>
                <span className="text-sm">{tier.formats}</span>
              </div>
              <div className="flex items-center gap-3">
                <span className="text-xs text-muted-foreground">
                  {tier.depth}
                </span>
                <Badge variant="secondary" className="text-xs">
                  {tier.status}
                </Badge>
              </div>
            </div>
          ))}
        </div>
      </section>

      <section>
        <h2 className="font-mono text-xl font-semibold">
          Detection Pipeline
        </h2>
        <div className="mt-4 grid gap-4 sm:grid-cols-3">
          <Card>
            <CardHeader>
              <CardTitle className="font-mono text-base">
                Stage 1 — Static
              </CardTitle>
            </CardHeader>
            <CardContent className="text-sm text-muted-foreground">
              Opcode-level analysis, graph traversal, pattern matching. Fast and
              deterministic. Every model passes through this stage.
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle className="font-mono text-base">
                Stage 2 — Heuristic
              </CardTitle>
            </CardHeader>
            <CardContent className="text-sm text-muted-foreground">
              Account reputation, typosquatting detection, metadata anomalies.
              Adjusts severity scoring and Stage 3 priority.
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle className="font-mono text-base">
                Stage 3 — Sandbox
              </CardTitle>
            </CardHeader>
            <CardContent className="text-sm text-muted-foreground">
              Isolated container execution with syscall tracing. Gold-standard
              evidence for disclosure. Critical/High findings only.
            </CardContent>
          </Card>
        </div>
      </section>
    </div>
  );
}
