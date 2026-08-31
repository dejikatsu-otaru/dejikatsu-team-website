ALTER TABLE cms_articles
  ADD COLUMN display_order INTEGER NOT NULL DEFAULT 0 CHECK (display_order BETWEEN -1000000 AND 1000000);

UPDATE cms_articles SET display_order = CASE id
  WHEN 'art_workshop_20260819' THEN 40
  WHEN 'art_digital_course_20260819' THEN 30
  WHEN 'art_town_news_20260819' THEN 20
  WHEN 'art_town_guide_20260819' THEN 10
  ELSE display_order
END;

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
      OR NEW.password_salt IS NULL OR length(NEW.password_salt) NOT BETWEEN 22 AND 64
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
      OR NEW.password_salt IS NULL OR length(NEW.password_salt) NOT BETWEEN 22 AND 64
      OR NEW.password_algorithm <> 'client-pbkdf2-sha256+hmac-sha256-v1'
      OR NEW.password_iterations <> 600000
    )
  )
BEGIN
  SELECT RAISE(ABORT, 'invalid_user_security_state');
END;

CREATE TRIGGER cms_article_actions_url_insert_guard
BEFORE INSERT ON cms_article_actions
WHEN
  NOT (NEW.url LIKE 'https://%' OR NEW.url LIKE '/assets/%')
  OR substr(NEW.url, 1, 2) = '//'
  OR instr(NEW.url, char(0)) > 0
  OR instr(NEW.url, char(10)) > 0
  OR instr(NEW.url, char(13)) > 0
  OR instr(NEW.url, '\') > 0
BEGIN
  SELECT RAISE(ABORT, 'unsafe_article_action_url');
END;

CREATE TRIGGER cms_article_actions_url_update_guard
BEFORE UPDATE OF url ON cms_article_actions
WHEN
  NOT (NEW.url LIKE 'https://%' OR NEW.url LIKE '/assets/%')
  OR substr(NEW.url, 1, 2) = '//'
  OR instr(NEW.url, char(0)) > 0
  OR instr(NEW.url, char(10)) > 0
  OR instr(NEW.url, char(13)) > 0
  OR instr(NEW.url, '\') > 0
BEGIN
  SELECT RAISE(ABORT, 'unsafe_article_action_url');
END;

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
  OR length(COALESCE(NEW.body_source, '')) > 100000
  OR length(COALESCE(NEW.body_html, '')) > 150000
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
  OR length(COALESCE(NEW.body_source, '')) > 100000
  OR length(COALESCE(NEW.body_html, '')) > 150000
  OR NOT (
    (NEW.status = 'draft' AND NEW.deleted_at IS NULL)
    OR (NEW.status = 'published' AND NEW.published_at IS NOT NULL AND NEW.deleted_at IS NULL)
    OR (NEW.status = 'unpublished' AND NEW.unpublished_at IS NOT NULL AND NEW.deleted_at IS NULL)
    OR (NEW.status = 'deleted' AND NEW.deleted_at IS NOT NULL)
  )
BEGIN
  SELECT RAISE(ABORT, 'invalid_article_security_state');
END;

CREATE TRIGGER cms_media_integrity_insert_guard
BEFORE INSERT ON cms_media
WHEN
  length(NEW.data) <> NEW.byte_size
  OR length(NEW.data) NOT BETWEEN 1 AND 1500000
  OR length(NEW.sha256) <> 43
  OR length(NEW.original_name) NOT BETWEEN 1 AND 255
  OR NEW.width > 1920
  OR NEW.height > 1920
  OR NEW.width * NEW.height > 3686400
BEGIN
  SELECT RAISE(ABORT, 'invalid_media_integrity');
END;

CREATE TRIGGER cms_media_integrity_update_guard
BEFORE UPDATE OF data, byte_size, sha256, original_name, width, height ON cms_media
WHEN
  length(NEW.data) <> NEW.byte_size
  OR length(NEW.data) NOT BETWEEN 1 AND 1500000
  OR length(NEW.sha256) <> 43
  OR length(NEW.original_name) NOT BETWEEN 1 AND 255
  OR NEW.width > 1920
  OR NEW.height > 1920
  OR NEW.width * NEW.height > 3686400
BEGIN
  SELECT RAISE(ABORT, 'invalid_media_integrity');
END;

CREATE TRIGGER cms_article_revisions_size_insert_guard
BEFORE INSERT ON cms_article_revisions
WHEN length(NEW.snapshot_json) > 180000
BEGIN
  SELECT RAISE(ABORT, 'article_revision_too_large');
END;

CREATE TRIGGER cms_audit_details_size_insert_guard
BEFORE INSERT ON cms_audit_logs
WHEN length(NEW.details_json) > 20000
BEGIN
  SELECT RAISE(ABORT, 'audit_details_too_large');
END;

INSERT OR REPLACE INTO cms_schema_metadata (key, value, updated_at)
VALUES ('schema_version', '2', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));
