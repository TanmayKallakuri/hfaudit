import { serve } from "https://deno.land/std@0.177.0/http/server.ts";

serve(async (_req) => {
  // TODO: Aggregate findings by severity
  // TODO: Update scan_stats table
  return new Response(
    JSON.stringify({ status: "ok", message: "Stats refresh stub" }),
    { headers: { "Content-Type": "application/json" } },
  );
});
