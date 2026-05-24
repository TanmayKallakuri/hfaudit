import { getSupabase } from "./supabase";
import type { Finding, ScanStat, Rule } from "@/types/finding";

export async function getLatestStats(): Promise<ScanStat | null> {
  const supabase = getSupabase();
  if (!supabase) return null;

  const { data, error } = await supabase
    .from("scan_stats")
    .select("*")
    .order("stat_date", { ascending: false })
    .limit(1)
    .single();

  if (error || !data) return null;
  return data as ScanStat;
}

export async function getPublishedFindings(): Promise<Finding[]> {
  const supabase = getSupabase();
  if (!supabase) return [];

  const { data, error } = await supabase
    .from("findings")
    .select("*")
    .eq("disclosure_status", "published")
    .order("published_at", { ascending: false });

  if (error || !data) return [];
  return data as Finding[];
}

export async function getFindingById(id: string): Promise<Finding | null> {
  const supabase = getSupabase();
  if (!supabase) return null;

  const { data, error } = await supabase
    .from("findings")
    .select("*")
    .eq("id", id)
    .eq("disclosure_status", "published")
    .single();

  if (error || !data) return null;
  return data as Finding;
}

export async function getRules(): Promise<Rule[]> {
  const supabase = getSupabase();
  if (!supabase) return [];

  const { data, error } = await supabase
    .from("rules")
    .select("*")
    .eq("active", true)
    .order("id", { ascending: true });

  if (error || !data) return [];
  return data as Rule[];
}

export async function getRulesCount(): Promise<number> {
  const supabase = getSupabase();
  if (!supabase) return 0;

  const { count, error } = await supabase
    .from("rules")
    .select("*", { count: "exact", head: true })
    .eq("active", true);

  if (error || count === null) return 0;
  return count;
}
