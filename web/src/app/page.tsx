import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

const stats = [
  { label: "Models Scanned", value: "—", description: "Scanning begins soon" },
  { label: "Active Rules", value: "1", description: "Detection rules loaded" },
  { label: "Findings", value: "0", description: "Published findings" },
  {
    label: "Disclosures",
    value: "0",
    description: "Under coordinated disclosure",
  },
];

const coverageTiers = [
  {
    tier: 1,
    formats: "PyTorch (.pt, .pth, .bin, .ckpt)",
    depth: "Deep",
    status: "planned" as const,
  },
  {
    tier: 1,
    formats: "TensorFlow SavedModel (.pb)",
    depth: "Deep",
    status: "planned" as const,
  },
  {
    tier: 2,
    formats: "Keras (.h5, .keras)",
    depth: "Rigorous",
    status: "planned" as const,
  },
  {
    tier: 3,
    formats: "ONNX, GGUF, safetensors",
    depth: "Light",
    status: "planned" as const,
  },
];

export default function Home() {
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

      <section className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {stats.map((stat) => (
          <Card key={stat.label}>
            <CardHeader className="pb-2">
              <CardDescription>{stat.label}</CardDescription>
              <CardTitle className="font-mono text-3xl">{stat.value}</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-xs text-muted-foreground">
                {stat.description}
              </p>
            </CardContent>
          </Card>
        ))}
      </section>

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
