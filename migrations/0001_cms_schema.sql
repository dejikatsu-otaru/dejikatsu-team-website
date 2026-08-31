PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS cms_schema_metadata (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
) STRICT;

CREATE TABLE IF NOT EXISTS cms_users (
  id TEXT PRIMARY KEY,
  login_id TEXT NOT NULL COLLATE NOCASE,
  real_name TEXT NOT NULL,
  job_title TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('owner', 'master', 'operator', 'reporter')),
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'active', 'disabled')),
  is_fixed_owner INTEGER NOT NULL DEFAULT 0 CHECK (is_fixed_owner IN (0, 1)),
  password_hash TEXT,
  password_salt TEXT,
  password_algorithm TEXT,
  password_iterations INTEGER,
  password_changed_at TEXT,
  force_password_change INTEGER NOT NULL DEFAULT 0 CHECK (force_password_change IN (0, 1)),
  markdown_auto_convert INTEGER NOT NULL DEFAULT 1 CHECK (markdown_auto_convert IN (0, 1)),
  created_by TEXT REFERENCES cms_users(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1),
  CHECK (length(login_id) BETWEEN 4 AND 64),
  CHECK (length(real_name) BETWEEN 1 AND 100),
  CHECK (length(job_title) BETWEEN 1 AND 100),
  CHECK ((role = 'owner' AND is_fixed_owner = 1) OR (role <> 'owner' AND is_fixed_owner = 0))
) STRICT;

CREATE UNIQUE INDEX IF NOT EXISTS cms_users_login_unique
  ON cms_users(lower(login_id));
CREATE UNIQUE INDEX IF NOT EXISTS cms_users_single_fixed_owner
  ON cms_users(is_fixed_owner) WHERE is_fixed_owner = 1;
CREATE INDEX IF NOT EXISTS cms_users_role_status_idx
  ON cms_users(role, status);

CREATE TRIGGER IF NOT EXISTS cms_users_fixed_owner_update_guard
BEFORE UPDATE ON cms_users
WHEN OLD.is_fixed_owner = 1 AND (
  NEW.is_fixed_owner <> 1 OR NEW.role <> 'owner' OR NEW.status <> 'active'
)
BEGIN
  SELECT RAISE(ABORT, 'fixed_owner_immutable');
END;

CREATE TRIGGER IF NOT EXISTS cms_users_fixed_owner_delete_guard
BEFORE DELETE ON cms_users
WHEN OLD.is_fixed_owner = 1
BEGIN
  SELECT RAISE(ABORT, 'fixed_owner_cannot_be_deleted');
END;

CREATE TABLE IF NOT EXISTS cms_sessions (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES cms_users(id) ON DELETE CASCADE,
  csrf_token_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  idle_expires_at TEXT NOT NULL,
  absolute_expires_at TEXT NOT NULL,
  ip_hash TEXT,
  user_agent_hash TEXT
) STRICT;

CREATE INDEX IF NOT EXISTS cms_sessions_user_idx ON cms_sessions(user_id);
CREATE INDEX IF NOT EXISTS cms_sessions_expiry_idx ON cms_sessions(absolute_expires_at);

CREATE TABLE IF NOT EXISTS cms_user_tokens (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES cms_users(id) ON DELETE CASCADE,
  purpose TEXT NOT NULL CHECK (purpose IN ('activate', 'reset_password')),
  created_by TEXT REFERENCES cms_users(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT
) STRICT;

CREATE INDEX IF NOT EXISTS cms_user_tokens_user_idx ON cms_user_tokens(user_id, purpose);
CREATE INDEX IF NOT EXISTS cms_user_tokens_expiry_idx ON cms_user_tokens(expires_at);

CREATE TABLE IF NOT EXISTS cms_login_attempts (
  scope_hash TEXT PRIMARY KEY,
  failure_count INTEGER NOT NULL DEFAULT 0 CHECK (failure_count >= 0),
  window_started_at TEXT NOT NULL,
  locked_until TEXT,
  updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS cms_media (
  id TEXT PRIMARY KEY,
  owner_user_id TEXT NOT NULL REFERENCES cms_users(id) ON DELETE RESTRICT,
  original_name TEXT NOT NULL,
  mime_type TEXT NOT NULL CHECK (mime_type = 'image/webp'),
  byte_size INTEGER NOT NULL CHECK (byte_size BETWEEN 1 AND 1500000),
  width INTEGER NOT NULL CHECK (width BETWEEN 1 AND 4096),
  height INTEGER NOT NULL CHECK (height BETWEEN 1 AND 4096),
  sha256 TEXT NOT NULL,
  data BLOB NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  deleted_at TEXT,
  deleted_by TEXT REFERENCES cms_users(id) ON DELETE SET NULL
) STRICT;

CREATE INDEX IF NOT EXISTS cms_media_owner_idx ON cms_media(owner_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS cms_media_sha_idx ON cms_media(sha256);

CREATE TABLE IF NOT EXISTS cms_articles (
  id TEXT PRIMARY KEY,
  slug TEXT NOT NULL COLLATE NOCASE,
  content_kind TEXT NOT NULL DEFAULT 'article' CHECK (content_kind IN ('article', 'legacy_link')),
  title TEXT NOT NULL,
  subtitle TEXT NOT NULL DEFAULT '',
  summary TEXT NOT NULL,
  category TEXT NOT NULL,
  body_source TEXT,
  body_format TEXT NOT NULL CHECK (body_format IN ('markdown', 'html', 'none')),
  body_html TEXT,
  sanitizer_version TEXT,
  markdown_auto_convert INTEGER NOT NULL DEFAULT 1 CHECK (markdown_auto_convert IN (0, 1)),
  cover_media_id TEXT REFERENCES cms_media(id) ON DELETE SET NULL,
  legacy_cover_path TEXT,
  cover_alt TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'published', 'unpublished', 'deleted')),
  created_by TEXT REFERENCES cms_users(id) ON DELETE SET NULL,
  updated_by TEXT REFERENCES cms_users(id) ON DELETE SET NULL,
  deleted_by TEXT REFERENCES cms_users(id) ON DELETE SET NULL,
  author_name_snapshot TEXT NOT NULL,
  author_job_title_snapshot TEXT NOT NULL,
  published_at TEXT,
  unpublished_at TEXT,
  deleted_at TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1),
  CHECK (length(slug) BETWEEN 3 AND 120),
  CHECK (length(title) BETWEEN 1 AND 160),
  CHECK (length(subtitle) <= 240),
  CHECK (length(summary) BETWEEN 1 AND 500),
  CHECK (length(category) BETWEEN 1 AND 80),
  CHECK (length(cover_alt) BETWEEN 1 AND 300),
  CHECK (
    (content_kind = 'article' AND body_format IN ('markdown', 'html') AND body_source IS NOT NULL AND length(trim(body_source)) > 0 AND body_html IS NOT NULL)
    OR
    (content_kind = 'legacy_link' AND body_format = 'none' AND body_source IS NULL AND body_html IS NULL)
  )
) STRICT;

CREATE UNIQUE INDEX IF NOT EXISTS cms_articles_slug_unique ON cms_articles(lower(slug));
CREATE INDEX IF NOT EXISTS cms_articles_public_idx
  ON cms_articles(status, published_at DESC, id);
CREATE INDEX IF NOT EXISTS cms_articles_owner_idx
  ON cms_articles(created_by, status, updated_at DESC);

CREATE TRIGGER IF NOT EXISTS cms_articles_created_by_immutable
BEFORE UPDATE OF created_by ON cms_articles
WHEN NEW.created_by IS NOT OLD.created_by
BEGIN
  SELECT RAISE(ABORT, 'article_owner_immutable');
END;

CREATE TRIGGER IF NOT EXISTS cms_articles_content_kind_immutable
BEFORE UPDATE OF content_kind ON cms_articles
WHEN NEW.content_kind <> OLD.content_kind
BEGIN
  SELECT RAISE(ABORT, 'article_content_kind_immutable');
END;

CREATE TABLE IF NOT EXISTS cms_article_actions (
  id TEXT PRIMARY KEY,
  article_id TEXT NOT NULL REFERENCES cms_articles(id) ON DELETE CASCADE,
  label TEXT NOT NULL,
  url TEXT NOT NULL,
  behavior TEXT NOT NULL CHECK (behavior IN ('same_tab', 'new_tab', 'download')),
  style TEXT NOT NULL DEFAULT 'primary' CHECK (style IN ('primary', 'secondary')),
  sort_order INTEGER NOT NULL DEFAULT 0,
  CHECK (length(label) BETWEEN 1 AND 80),
  CHECK (length(url) BETWEEN 1 AND 2048)
) STRICT;

CREATE INDEX IF NOT EXISTS cms_article_actions_article_idx
  ON cms_article_actions(article_id, sort_order, id);

CREATE TABLE IF NOT EXISTS cms_article_media (
  article_id TEXT NOT NULL REFERENCES cms_articles(id) ON DELETE CASCADE,
  media_id TEXT NOT NULL REFERENCES cms_media(id) ON DELETE RESTRICT,
  placement TEXT NOT NULL CHECK (placement IN ('body', 'cover')),
  alt_text TEXT NOT NULL,
  caption TEXT NOT NULL DEFAULT '',
  sort_order INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (article_id, media_id, placement),
  CHECK (length(alt_text) BETWEEN 1 AND 300),
  CHECK (length(caption) <= 500)
) STRICT;

CREATE INDEX IF NOT EXISTS cms_article_media_media_idx ON cms_article_media(media_id);

CREATE TABLE IF NOT EXISTS cms_article_revisions (
  id TEXT PRIMARY KEY,
  article_id TEXT NOT NULL REFERENCES cms_articles(id) ON DELETE CASCADE,
  article_version INTEGER NOT NULL,
  snapshot_json TEXT NOT NULL CHECK (json_valid(snapshot_json)),
  created_by TEXT REFERENCES cms_users(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  UNIQUE (article_id, article_version)
) STRICT;

CREATE INDEX IF NOT EXISTS cms_article_revisions_article_idx
  ON cms_article_revisions(article_id, article_version DESC);

CREATE TABLE IF NOT EXISTS cms_audit_logs (
  id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL,
  actor_user_id TEXT REFERENCES cms_users(id) ON DELETE SET NULL,
  actor_role TEXT,
  action TEXT NOT NULL,
  target_type TEXT NOT NULL,
  target_id TEXT,
  outcome TEXT NOT NULL CHECK (outcome IN ('success', 'denied', 'failure')),
  details_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(details_json)),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
) STRICT;

CREATE INDEX IF NOT EXISTS cms_audit_logs_created_idx ON cms_audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS cms_audit_logs_actor_idx ON cms_audit_logs(actor_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS cms_audit_logs_target_idx ON cms_audit_logs(target_type, target_id, created_at DESC);

CREATE TRIGGER IF NOT EXISTS cms_audit_logs_update_guard
BEFORE UPDATE ON cms_audit_logs
BEGIN
  SELECT RAISE(ABORT, 'audit_log_is_append_only');
END;

CREATE TRIGGER IF NOT EXISTS cms_audit_logs_delete_guard
BEFORE DELETE ON cms_audit_logs
BEGIN
  SELECT RAISE(ABORT, 'audit_log_is_append_only');
END;

INSERT OR REPLACE INTO cms_schema_metadata (key, value, updated_at)
VALUES ('schema_version', '1', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));

INSERT OR IGNORE INTO cms_articles (
  id, slug, content_kind, title, subtitle, summary, category,
  body_source, body_format, body_html, sanitizer_version, markdown_auto_convert,
  legacy_cover_path, cover_alt, status, author_name_snapshot, author_job_title_snapshot,
  published_at, created_at, updated_at, version
) VALUES
(
  'art_workshop_20260819',
  'community-youth-workshop-2026',
  'legacy_link',
  '第２回地域と若者が創る新しい町内会のカタチ参加者募集',
  '地域の危機を共有し、次のアクションを決めるワークショップ',
  '小樽潮陵高校DXルームにおいて、若者と大人が「地域の危機」を共有し、デジ活チームの仲間を増やすための具体的なアクションプラン（認知向上策）を決定します。9月12日（土）開催。',
  '参加者募集',
  NULL, 'none', NULL, NULL, 0,
  '/assets/activity-workshop-flyer.png',
  '第2回 地域と若者が創る新しい町内会のカタチ ワークショップのチラシ',
  'published', 'デジ活チーム', '運営',
  '2026-08-18T15:00:00.000Z', '2026-08-18T15:00:00.000Z', '2026-08-18T15:00:00.000Z', 1
),
(
  'art_digital_course_20260819',
  'digitalization-support-course-2026',
  'article',
  '町会活動デジタル化支援講座参加者募集',
  '若い世代の参加につなげる、パソコン・スマホ活用講座',
  'パソコンやスマホを活用して、回覧板の情報やイベント情報を配信することで、若い世代の町会活動への参加を促すための方法を学びます。10月31日（土）開催。',
  '参加者募集',
  'パソコンやスマホを活用して、回覧板の情報やイベント情報を配信することで、若い世代の町会活動への参加を促すための方法を学びます。10月31日（土）開催。',
  'markdown',
  '<p>パソコンやスマホを活用して、回覧板の情報やイベント情報を配信することで、若い世代の町会活動への参加を促すための方法を学びます。10月31日（土）開催。</p>',
  'cms-allowlist-v1', 1,
  '/assets/activity-digital-course.png',
  '町会活動のデジタル化について講習会を行う様子',
  'published', 'デジ活チーム', '運営',
  '2026-08-18T15:00:00.000Z', '2026-08-18T15:00:00.000Z', '2026-08-18T15:00:00.000Z', 1
),
(
  'art_town_news_20260819',
  'town-news-app-release',
  'legacy_link',
  '「まちの新聞づくり」をリリースしました',
  'スマホで簡単に電子回覧板を作成できるβ版アプリ',
  '「まちの新聞づくり」は、ご高齢の役員でも簡単にスマホで電子回覧板を作成できるアプリを目指しています。当面はβ版で運用し、利用者からのご意見をいただきながら完成度を高めて参ります。',
  'デジタルツール',
  NULL, 'none', NULL, NULL, 0,
  '/assets/activity-town-newspaper.jpg',
  '町内会のお知らせをA4とPDFで作成できる、まち新聞の画面',
  'published', 'デジ活チーム', '運営',
  '2026-08-18T15:00:00.000Z', '2026-08-18T15:00:00.000Z', '2026-08-18T15:00:00.000Z', 1
),
(
  'art_town_guide_20260819',
  'town-association-guide-release',
  'article',
  '「町内会まるわかりシート」をリリースしました',
  '町内会の役割と課題を、ひと目でわかりやすく',
  '「町内会まるわかりシート」は、「地域と若者が創る新しい町内会のカタチ」において話し合われた内容から、町内会の役割と課題をわかりやすくまとめたものです。転入した方への説明などにご活用ください。',
  'デジタルツール',
  '「町内会まるわかりシート」は、「地域と若者が創る新しい町内会のカタチ」において話し合われた内容から、町内会の役割と課題をわかりやすくまとめたものです。転入した方への説明などにご活用ください。',
  'markdown',
  '<p>「町内会まるわかりシート」は、「地域と若者が創る新しい町内会のカタチ」において話し合われた内容から、町内会の役割と課題をわかりやすくまとめたものです。転入した方への説明などにご活用ください。</p>',
  'cms-allowlist-v1', 1,
  '/assets/activity-town-guide.png',
  '町内会まるわかりシートのイラスト',
  'published', 'デジ活チーム', '運営',
  '2026-08-18T15:00:00.000Z', '2026-08-18T15:00:00.000Z', '2026-08-18T15:00:00.000Z', 1
);

INSERT OR IGNORE INTO cms_article_actions (id, article_id, label, url, behavior, style, sort_order)
VALUES
  ('act_workshop_pdf', 'art_workshop_20260819', 'PDFをダウンロード', '/assets/第２回ワークショップチラシ（町会役員バージョン）.pdf', 'download', 'primary', 1),
  ('act_workshop_form', 'art_workshop_20260819', '参加申込', 'https://forms.gle/QkLGtUSfmZuz7pK17', 'new_tab', 'secondary', 2),
  ('act_town_news_app', 'art_town_news_20260819', '利用はこちらから', 'https://machi-shinbun.com/', 'new_tab', 'primary', 1);
