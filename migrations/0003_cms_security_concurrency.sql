PRAGMA foreign_keys = ON;

-- Request-scoped markers let every statement in a D1 batch prove that its own
-- optimistic update won, rather than mistaking another request's version bump
-- for success.
ALTER TABLE cms_users
  ADD COLUMN mutation_id TEXT CHECK (mutation_id IS NULL OR length(mutation_id) BETWEEN 16 AND 128);

ALTER TABLE cms_articles
  ADD COLUMN mutation_id TEXT CHECK (mutation_id IS NULL OR length(mutation_id) BETWEEN 16 AND 128);

-- Earlier builds used logical media deletion. Once delete is made physical,
-- reclaim any already-deleted, unreferenced BLOBs so they cannot consume the
-- D1 quota indefinitely.
DELETE FROM cms_media
WHERE deleted_at IS NOT NULL
  AND NOT EXISTS (SELECT 1 FROM cms_articles a WHERE a.cover_media_id = cms_media.id)
  AND NOT EXISTS (SELECT 1 FROM cms_article_media am WHERE am.media_id = cms_media.id);

DROP TRIGGER cms_users_security_insert_guard;
DROP TRIGGER cms_users_security_update_guard;

CREATE TRIGGER cms_users_security_insert_guard
BEFORE INSERT ON cms_users
WHEN
  (NEW.role = 'owner' AND (NEW.is_fixed_owner <> 1 OR NEW.status <> 'active'))
  OR (NEW.role <> 'owner' AND NEW.is_fixed_owner <> 0)
  OR (NEW.login_id <> lower(NEW.login_id))
  OR (NEW.login_id GLOB '*[^a-z0-9._-]*')
  OR (NEW.login_id GLOB '[^a-z0-9]*')
  OR (
    NEW.status = 'active' AND (
      NEW.password_hash IS NULL OR length(NEW.password_hash) <> 43
      OR NEW.password_salt IS NULL OR length(NEW.password_salt) <> 43
      OR NEW.password_algorithm <> 'client-pbkdf2-sha256+hmac-sha256-v1'
      OR NEW.password_iterations <> 600000
    )
  )
BEGIN
  SELECT RAISE(ABORT, 'invalid_user_security_state');
END;

CREATE TRIGGER cms_users_security_update_guard
BEFORE UPDATE ON cms_users
WHEN
  (NEW.role = 'owner' AND (NEW.is_fixed_owner <> 1 OR NEW.status <> 'active'))
  OR (NEW.role <> 'owner' AND NEW.is_fixed_owner <> 0)
  OR (NEW.login_id <> lower(NEW.login_id))
  OR (NEW.login_id GLOB '*[^a-z0-9._-]*')
  OR (NEW.login_id GLOB '[^a-z0-9]*')
  OR (
    NEW.status = 'active' AND (
      NEW.password_hash IS NULL OR length(NEW.password_hash) <> 43
      OR NEW.password_salt IS NULL OR length(NEW.password_salt) <> 43
      OR NEW.password_algorithm <> 'client-pbkdf2-sha256+hmac-sha256-v1'
      OR NEW.password_iterations <> 600000
    )
  )
BEGIN
  SELECT RAISE(ABORT, 'invalid_user_security_state');
END;

DROP TRIGGER cms_articles_security_insert_guard;
DROP TRIGGER cms_articles_security_update_guard;

CREATE TRIGGER cms_articles_security_insert_guard
BEFORE INSERT ON cms_articles
WHEN
  NEW.slug <> lower(NEW.slug)
  OR NEW.slug GLOB '*[^a-z0-9-]*'
  OR substr(NEW.slug, 1, 1) = '-'
  OR substr(NEW.slug, -1, 1) = '-'
  OR (NEW.legacy_cover_path IS NOT NULL AND (
    NEW.legacy_cover_path NOT LIKE '/assets/%'
    OR instr(NEW.legacy_cover_path, '..') > 0
    OR instr(NEW.legacy_cover_path, '\') > 0
  ))
  OR length(COALESCE(NEW.body_source, '')) > 10000
  OR length(COALESCE(NEW.body_html, '')) > 25000
  OR NOT (
    (NEW.status = 'draft' AND NEW.deleted_at IS NULL)
    OR (NEW.status = 'published' AND NEW.published_at IS NOT NULL AND NEW.deleted_at IS NULL)
    OR (NEW.status = 'unpublished' AND NEW.unpublished_at IS NOT NULL AND NEW.deleted_at IS NULL)
    OR (NEW.status = 'deleted' AND NEW.deleted_at IS NOT NULL)
  )
BEGIN
  SELECT RAISE(ABORT, 'invalid_article_security_state');
END;

CREATE TRIGGER cms_articles_security_update_guard
BEFORE UPDATE ON cms_articles
WHEN
  NEW.slug <> lower(NEW.slug)
  OR NEW.slug GLOB '*[^a-z0-9-]*'
  OR substr(NEW.slug, 1, 1) = '-'
  OR substr(NEW.slug, -1, 1) = '-'
  OR (NEW.legacy_cover_path IS NOT NULL AND (
    NEW.legacy_cover_path NOT LIKE '/assets/%'
    OR instr(NEW.legacy_cover_path, '..') > 0
    OR instr(NEW.legacy_cover_path, '\') > 0
  ))
  OR length(COALESCE(NEW.body_source, '')) > 10000
  OR length(COALESCE(NEW.body_html, '')) > 25000
  OR NOT (
    (NEW.status = 'draft' AND NEW.deleted_at IS NULL)
    OR (NEW.status = 'published' AND NEW.published_at IS NOT NULL AND NEW.deleted_at IS NULL)
    OR (NEW.status = 'unpublished' AND NEW.unpublished_at IS NOT NULL AND NEW.deleted_at IS NULL)
    OR (NEW.status = 'deleted' AND NEW.deleted_at IS NOT NULL)
  )
BEGIN
  SELECT RAISE(ABORT, 'invalid_article_security_state');
END;

-- Only the two repository-owned seed bodies are known byte-for-byte here.
-- User-authored rows must never be relabelled without running the sanitizer.
UPDATE cms_articles
SET sanitizer_version = 'cms-allowlist-v2-sanitize-html-2'
WHERE id IN ('art_digital_course_20260819', 'art_town_guide_20260819')
  AND content_kind = 'article';

INSERT OR REPLACE INTO cms_schema_metadata (key, value, updated_at)
VALUES ('schema_version', '3', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));
