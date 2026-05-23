import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

export default function MethodologyPage() {
  return (
    <div className="space-y-10">
      <section>
        <h1 className="font-mono text-3xl font-bold tracking-tight">
          Detection Methodology
        </h1>
        <p className="mt-2 max-w-2xl text-muted-foreground">
          HFAudit uses a three-stage detection pipeline. Every model passes
          through Stage 1. Only hits proceed to subsequent stages.
        </p>
      </section>

      <section className="space-y-6">
        <Card>
          <CardHeader>
            <CardTitle className="font-mono">
              Stage 1 — Static Analysis
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 text-sm text-muted-foreground">
            <p>
              Fast, deterministic, defendable. Per-format detectors scan model
              files without executing them. Detection rules are defined in YAML
              and loaded at runtime.
            </p>
            <ul className="list-inside list-disc space-y-1">
              <li>
                PyTorch pickle: opcode-level analysis of __reduce__ callables
              </li>
              <li>
                TensorFlow SavedModel: graph traversal with op allowlist
              </li>
              <li>Keras: Lambda layer identification and code inspection</li>
              <li>ONNX: custom operator domain detection</li>
              <li>GGUF: metadata anomaly detection</li>
              <li>safetensors: format guarantee verification</li>
            </ul>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="font-mono">
              Stage 2 — Heuristic and Reputation Signals
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 text-sm text-muted-foreground">
            <p>
              Probabilistic signals that adjust priority and severity. Stage 2
              does not condemn a model alone.
            </p>
            <ul className="list-inside list-disc space-y-1">
              <li>Account age, upload count, download velocity</li>
              <li>Model name similarity to popular models (typosquatting)</li>
              <li>Upload metadata anomalies</li>
              <li>Cross-reference with previously flagged accounts</li>
            </ul>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="font-mono">
              Stage 3 — Sandboxed Dynamic Analysis
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 text-sm text-muted-foreground">
            <p>
              Reserved for Critical/High hits or strong Stage 2 corroboration.
              Models are loaded in an isolated container with full syscall
              tracing.
            </p>
            <ul className="list-inside list-disc space-y-1">
              <li>No network access (DNS sinkholed)</li>
              <li>Read-only filesystem except tmpfs workspace</li>
              <li>CPU, memory, and wall-clock limits</li>
              <li>
                Confirmed malicious: process execution, network connects,
                unauthorized writes
              </li>
            </ul>
          </CardContent>
        </Card>
      </section>

      <section>
        <h2 className="font-mono text-xl font-semibold">Severity Rubric</h2>
        <div className="mt-4 overflow-x-auto rounded-lg border border-border">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/50">
                <th className="px-4 py-3 text-left font-mono font-medium">
                  Severity
                </th>
                <th className="px-4 py-3 text-left font-medium">Definition</th>
                <th className="px-4 py-3 text-left font-medium">
                  Public Disclosure
                </th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border">
                <td className="px-4 py-3 font-mono text-red-400">Critical</td>
                <td className="px-4 py-3 text-muted-foreground">
                  Confirmed code execution primitive, exploitable
                </td>
                <td className="px-4 py-3 text-muted-foreground">
                  Named after disclosure window
                </td>
              </tr>
              <tr className="border-b border-border">
                <td className="px-4 py-3 font-mono text-orange-400">High</td>
                <td className="px-4 py-3 text-muted-foreground">
                  Strong malicious indicators, multiple signals
                </td>
                <td className="px-4 py-3 text-muted-foreground">
                  Named after disclosure window
                </td>
              </tr>
              <tr className="border-b border-border">
                <td className="px-4 py-3 font-mono text-yellow-400">Medium</td>
                <td className="px-4 py-3 text-muted-foreground">
                  Suspicious patterns, warrants investigation
                </td>
                <td className="px-4 py-3 text-muted-foreground">
                  Aggregate stats only
                </td>
              </tr>
              <tr className="border-b border-border">
                <td className="px-4 py-3 font-mono text-blue-400">Low</td>
                <td className="px-4 py-3 text-muted-foreground">
                  Anomalies, likely explainable
                </td>
                <td className="px-4 py-3 text-muted-foreground">
                  Aggregate stats only
                </td>
              </tr>
              <tr>
                <td className="px-4 py-3 font-mono text-muted-foreground">
                  Info
                </td>
                <td className="px-4 py-3 text-muted-foreground">
                  Format observations, no security impact
                </td>
                <td className="px-4 py-3 text-muted-foreground">
                  Internal only
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
