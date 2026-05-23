import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

export default function DisclosurePage() {
  return (
    <div className="space-y-10">
      <section>
        <h1 className="font-mono text-3xl font-bold tracking-tight">
          Disclosure Policy
        </h1>
        <p className="mt-2 max-w-2xl text-muted-foreground">
          HFAudit operates a coordinated vulnerability disclosure pipeline with
          the HuggingFace security team. This page describes that process.
        </p>
      </section>

      <section className="space-y-4">
        <h2 className="font-mono text-xl font-semibold">Workflow</h2>
        <div className="grid gap-3">
          {[
            {
              step: "1",
              title: "Detection",
              desc: "Multi-stage pipeline identifies a Critical or High severity finding.",
            },
            {
              step: "2",
              title: "Validation",
              desc: "Two independent reproductions required before any disclosure action.",
            },
            {
              step: "3",
              title: "ID Assignment",
              desc: "Finding receives an HFA-YYYY-NNNN identifier for tracking.",
            },
            {
              step: "4",
              title: "Vendor Notification",
              desc: "Technical analysis sent to HuggingFace security team with 90-day timeline.",
            },
            {
              step: "5",
              title: "Coordination",
              desc: "90-day window for the vendor to address the finding. Extensible by agreement.",
            },
            {
              step: "6",
              title: "Publication",
              desc: "Full writeup published after window closes or fix is confirmed.",
            },
          ].map((item) => (
            <div
              key={item.step}
              className="flex items-start gap-4 rounded-lg border border-border px-4 py-3"
            >
              <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-muted font-mono text-sm font-bold">
                {item.step}
              </span>
              <div>
                <p className="font-mono text-sm font-medium">{item.title}</p>
                <p className="text-sm text-muted-foreground">{item.desc}</p>
              </div>
            </div>
          ))}
        </div>
      </section>

      <section>
        <h2 className="font-mono text-xl font-semibold">Hard Rules</h2>
        <Card className="mt-4">
          <CardHeader>
            <CardTitle className="font-mono text-base">
              Non-Negotiable
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="space-y-2 text-sm text-muted-foreground">
              <li>
                No public naming of models or uploaders before the disclosure
                window closes.
              </li>
              <li>
                No screenshots of malicious payloads on social media before
                publication.
              </li>
              <li>
                HuggingFace security team credited in every published writeup.
              </li>
              <li>
                Every published finding includes a complete disclosure timeline.
              </li>
            </ul>
          </CardContent>
        </Card>
      </section>

      <section>
        <h2 className="font-mono text-xl font-semibold">Report a Finding</h2>
        <Card className="mt-4">
          <CardContent className="pt-6">
            <p className="text-sm text-muted-foreground">
              If you have discovered a malicious model on HuggingFace and would
              like HFAudit to assist with coordinated disclosure, contact us at{" "}
              <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">
                disclosure@hfaudit.dev
              </code>{" "}
              with the model identifier and a brief description of the malicious
              behavior.
            </p>
          </CardContent>
        </Card>
      </section>
    </div>
  );
}
