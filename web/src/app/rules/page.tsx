import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

const rules = [
  {
    id: "HFA-PKL-001",
    severity: "critical" as const,
    category: "pickle.reduce.dangerous_callable",
    description:
      "Pickle __reduce__ invokes a known-dangerous callable (os.system, subprocess.Popen, eval, exec, etc.)",
    targets: [
      "os.system",
      "subprocess.Popen",
      "eval",
      "exec",
      "__import__",
    ],
  },
];

const severityColor: Record<string, string> = {
  critical: "text-red-400 border-red-400/30",
  high: "text-orange-400 border-orange-400/30",
  medium: "text-yellow-400 border-yellow-400/30",
  low: "text-blue-400 border-blue-400/30",
  informational: "text-muted-foreground",
};

export default function RulesPage() {
  return (
    <div className="space-y-8">
      <section>
        <h1 className="font-mono text-3xl font-bold tracking-tight">
          Detection Rules
        </h1>
        <p className="mt-2 max-w-2xl text-muted-foreground">
          Public detection ruleset. Rules are defined in YAML and loaded at
          runtime. Every rule includes known bypass techniques and false positive
          conditions.
        </p>
      </section>

      <div className="space-y-4">
        {rules.map((rule) => (
          <Card key={rule.id}>
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle className="font-mono text-base">
                  {rule.id}
                </CardTitle>
                <Badge
                  variant="outline"
                  className={severityColor[rule.severity]}
                >
                  {rule.severity}
                </Badge>
              </div>
              <p className="text-xs font-mono text-muted-foreground">
                {rule.category}
              </p>
            </CardHeader>
            <CardContent className="space-y-3">
              <p className="text-sm text-muted-foreground">
                {rule.description}
              </p>
              <div className="flex flex-wrap gap-2">
                {rule.targets.map((target) => (
                  <code
                    key={target}
                    className="rounded bg-muted px-2 py-0.5 font-mono text-xs"
                  >
                    {target}
                  </code>
                ))}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      <p className="text-sm text-muted-foreground">
        More rules are under development. See the{" "}
        <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">
          scanner/rules/
        </code>{" "}
        directory for the full YAML definitions.
      </p>
    </div>
  );
}
