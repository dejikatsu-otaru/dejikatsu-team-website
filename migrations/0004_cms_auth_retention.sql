PRAGMA foreign_keys = ON;

-- Authentication scopes are privacy-preserving HMACs, but unauthenticated
-- traffic can still create many distinct rows. This index keeps the bounded,
-- opportunistic retention query efficient even after an abuse burst.
CREATE INDEX IF NOT EXISTS cms_login_attempts_updated_idx
  ON cms_login_attempts(updated_at);

INSERT OR REPLACE INTO cms_schema_metadata (key, value, updated_at)
VALUES ('schema_version', '4', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));
