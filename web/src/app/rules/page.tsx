import { RuleCard } from "@/components/rule-card";
import { getRules } from "@/lib/queries";

export default async function RulesPage() {
  const rules = await getRules();

  const grouped = rules.reduce<Record<string, typeof rules>>((acc, rule) => {
    const group = rule.category.split(".")[0];
    if (!acc[group]) acc[group] = [];
    acc[group].push(rule);
    return acc;
  }, {});

  const groupLabels: Record<string, string> = {
    pickle: "Pickle Deserialization",
    savedmodel: "TensorFlow SavedModel",
    keras: "Keras Lambda Layer",
    onnx: "ONNX Custom Ops",
    gguf: "GGUF Metadata",
    typosquat: "Typosquatting",
  };

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
        {rules.length > 0 && (
          <p className="mt-1 text-sm text-muted-foreground">
            {rules.length} active rules across{" "}
            {Object.keys(grouped).length} categories.
          </p>
        )}
      </section>

      {rules.length > 0 ? (
        Object.entries(grouped).map(([group, groupRules]) => (
          <section key={group}>
            <h2 className="font-mono text-lg font-semibold">
              {groupLabels[group] ?? group}
            </h2>
            <div className="mt-4 space-y-4">
              {groupRules.map((rule) => (
                <RuleCard key={rule.id} rule={rule} />
              ))}
            </div>
          </section>
        ))
      ) : (
        <div className="rounded-lg border border-border p-8 text-center">
          <p className="font-mono text-lg text-muted-foreground">
            Rules loading...
          </p>
          <p className="mt-2 text-sm text-muted-foreground">
            Detection rules will appear here once the scanner is connected. See
            the{" "}
            <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">
              scanner/rules/
            </code>{" "}
            directory for the full YAML definitions.
          </p>
        </div>
      )}
    </div>
  );
}
