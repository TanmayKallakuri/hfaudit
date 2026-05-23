# HFAudit Infrastructure

Supabase backend for the HFAudit security observatory.

## Migrations

Apply the initial schema to your Supabase project:

```bash
# Option A: Supabase CLI (requires linked project)
supabase db push

# Option B: Direct connection
psql -h <DB_HOST> -U postgres -d postgres -f infra/migrations/001_initial_schema.sql

# Option C: Paste into Supabase SQL Editor manually
```

Migrations are numbered sequentially (`001_`, `002_`, ...) and must be applied in order.

## Edge Functions

Deploy edge functions to Supabase:

```bash
supabase functions deploy daily-sweep
supabase functions deploy stats-refresh
```

To test locally:

```bash
supabase functions serve daily-sweep --no-verify-jwt
```

## Environment Variables

The following must be set in the Supabase project (Dashboard > Edge Functions > Secrets):

| Variable | Description |
|---|---|
| `HF_API_TOKEN` | HuggingFace API token for fetching model metadata |
| `SUPABASE_SERVICE_ROLE_KEY` | Auto-provided in edge functions |
| `SUPABASE_URL` | Auto-provided in edge functions |

## Dashboard

Manage the project at: https://supabase.com/dashboard
