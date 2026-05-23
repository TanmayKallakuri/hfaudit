-- HFAudit initial schema
-- Apply with: supabase db push --db-url <connection_string>
-- Or paste into Supabase SQL Editor manually.

BEGIN;

-- findings: individual scan findings tied to a model
CREATE TABLE findings (
    id TEXT PRIMARY KEY,
    model_id TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'informational')),
    rule_id TEXT NOT NULL,
    category TEXT NOT NULL,
    description TEXT NOT NULL,
    evidence TEXT NOT NULL,
    file_path TEXT NOT NULL,
    confidence FLOAT NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    "references" JSONB DEFAULT '[]'::jsonb,
    false_positive_notes TEXT DEFAULT '',
    bypass_notes TEXT DEFAULT '',
    disclosure_status TEXT NOT NULL DEFAULT 'internal' CHECK (disclosure_status IN ('internal', 'reported', 'acknowledged', 'fixed', 'published')),
    disclosure_id TEXT,
    published_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- scans: tracks scan jobs
CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    model_id TEXT NOT NULL,
    scan_type TEXT NOT NULL CHECK (scan_type IN ('new_upload', 'top_n', 'triggered', 'manual')),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed')),
    stage_reached INTEGER CHECK (stage_reached IS NULL OR stage_reached IN (1, 2, 3)),
    findings_count INTEGER DEFAULT 0,
    duration_ms INTEGER,
    error_message TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

-- rules: detection rule metadata synced from YAML
CREATE TABLE rules (
    id TEXT PRIMARY KEY,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    description TEXT NOT NULL,
    "references" JSONB DEFAULT '[]'::jsonb,
    false_positive_notes TEXT DEFAULT '',
    bypass_notes TEXT DEFAULT '',
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- accounts: HuggingFace account reputation tracking
CREATE TABLE accounts (
    username TEXT PRIMARY KEY,
    account_age_days INTEGER,
    upload_count INTEGER DEFAULT 0,
    flagged_count INTEGER DEFAULT 0,
    reputation_score FLOAT DEFAULT 0.5,
    first_seen TIMESTAMPTZ DEFAULT NOW(),
    last_seen TIMESTAMPTZ DEFAULT NOW(),
    notes TEXT DEFAULT '',
    metadata JSONB DEFAULT '{}'::jsonb
);

-- scan_stats: daily aggregate statistics for the dashboard
CREATE TABLE scan_stats (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stat_date DATE NOT NULL DEFAULT CURRENT_DATE,
    total_scanned INTEGER DEFAULT 0,
    findings_critical INTEGER DEFAULT 0,
    findings_high INTEGER DEFAULT 0,
    findings_medium INTEGER DEFAULT 0,
    findings_low INTEGER DEFAULT 0,
    findings_informational INTEGER DEFAULT 0,
    active_disclosures INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(stat_date)
);

-- Indexes for common query patterns
CREATE INDEX idx_findings_model_id ON findings(model_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_disclosure_status ON findings(disclosure_status);
CREATE INDEX idx_scans_model_id ON scans(model_id);
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_created_at ON scans(created_at);

-- Row Level Security
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_stats ENABLE ROW LEVEL SECURITY;

-- findings: public can only read published findings
CREATE POLICY "Public read published findings"
    ON findings FOR SELECT
    TO anon
    USING (disclosure_status = 'published');

-- findings: authenticated service role gets full access
CREATE POLICY "Service full access to findings"
    ON findings FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);

-- scans: no public access, service role only
CREATE POLICY "Service full access to scans"
    ON scans FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);

-- rules: public read access
CREATE POLICY "Public read rules"
    ON rules FOR SELECT
    TO anon
    USING (true);

CREATE POLICY "Service full access to rules"
    ON rules FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);

-- accounts: no public access, service role only
CREATE POLICY "Service full access to accounts"
    ON accounts FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);

-- scan_stats: public read access
CREATE POLICY "Public read scan_stats"
    ON scan_stats FOR SELECT
    TO anon
    USING (true);

CREATE POLICY "Service full access to scan_stats"
    ON scan_stats FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);

-- Auto-update updated_at on row modification
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER findings_updated_at
    BEFORE UPDATE ON findings
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER rules_updated_at
    BEFORE UPDATE ON rules
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

COMMIT;
