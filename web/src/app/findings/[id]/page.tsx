import { Badge } from "@/components/ui/badge";
import { notFound } from "next/navigation";

interface FindingPageProps {
  params: Promise<{ id: string }>;
}

export default async function FindingPage({ params }: FindingPageProps) {
  const { id } = await params;

  if (!id.startsWith("HFA-")) {
    notFound();
  }

  return (
    <div className="space-y-8">
      <section>
        <div className="flex items-center gap-3">
          <h1 className="font-mono text-3xl font-bold tracking-tight">{id}</h1>
          <Badge variant="outline">Not Found</Badge>
        </div>
        <p className="mt-2 text-muted-foreground">
          This finding has not been published yet, or does not exist. Findings
          are published after their coordinated disclosure window closes.
        </p>
      </section>
    </div>
  );
}
