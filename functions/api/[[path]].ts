import {
  actorFor,
  adminHeaders,
  BODY_SOURCE_MAX,
  type Actor,
  audit,
  body,
  constantTimeEqual,
  type Env,
  expiredCookie,
  expiredCsrfCookie,
  failure,
  fakePasswordSalt,
  HttpError,
  json,
  limitedRequestBytes,
  normalizeLogin,
  now,
  originGuard,
  PASSWORD_ALGORITHM,
  PASSWORD_ITERATIONS,
  privateScopeHash,
  protectVerifier,
  publicUser,
  randomId,
  renderBody,
  requireText,
  roleAtLeast,
  safeActionUrl,
  safeActionUrlForRead,
  safeLegacyCoverPath,
  SANITIZER_VERSION,
  secret,
  SESSION_ABSOLUTE_MS,
  SESSION_IDLE_MS,
  sessionCookie,
  csrfCookie,
  sha256,
  type User,
  validateClientCredential,
  validateLoginVerifier,
  validateSlug,
  verifyProtectedVerifier,
  webpDimensions,
} from "../lib/cms";

type Ctx = EventContext<Env, string, Record<string, unknown>>;
type ArticleKind = "article" | "legacy_link";
type ArticleStatus = "draft" | "published" | "unpublished" | "deleted";
type ArticleRow = Record<string, unknown> & {
  id: string;
  slug: string;
  content_kind: ArticleKind;
  title: string;
  subtitle: string;
  summary: string;
  category: string;
  body_source: string | null;
  body_format: "markdown" | "html" | "none";
  body_html: string | null;
  cover_media_id: string | null;
  legacy_cover_path: string | null;
  cover_alt: string;
  status: ArticleStatus;
  created_by: string | null;
  author_name_snapshot: string;
  author_job_title_snapshot: string;
  published_at: string | null;
  unpublished_at: string | null;
  deleted_at: string | null;
  created_at: string;
  updated_at: string;
  version: number;
  markdown_auto_convert: number;
  mutation_id: string | null;
};
type ParsedAction = { id: string; label: string; url: string; behavior: string; style: string; sortOrder: number };
type ParsedArticle = {
  slug: string;
  title: string;
  subtitle: string;
  summary: string;
  category: string;
  coverAlt: string;
  coverMediaId: string | null;
  bodySource: string | null;
  bodyFormat: "markdown" | "html" | "none";
  bodyHtml: string | null;
  markdownAutoConvert: number;
  actions: ParsedAction[];
};

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const ARTICLE_COLUMNS = `
  id, slug, content_kind, title, subtitle, summary, category,
  body_source, body_format, body_html, cover_media_id, legacy_cover_path, cover_alt,
  status, created_by, updated_by, author_name_snapshot, author_job_title_snapshot,
  published_at, unpublished_at, deleted_at, created_at, updated_at, version,
  markdown_auto_convert, mutation_id
`;
const PUBLIC_PREDICATE = "status = 'published' AND published_at IS NOT NULL AND deleted_at IS NULL";
const ARTICLE_INPUT_KEYS = new Set([
  "id", "version", "contentKind", "slug", "title", "subtitle", "summary", "category",
  "coverAlt", "coverMediaId", "bodyHtml", "bodySource", "bodyFormat", "markdownAutoConvert", "actions",
]);

function assertKeys(input: unknown, allowed: Set<string>): asserts input is Record<string, unknown> {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new HttpError(400, "invalid_request", "入力内容を確認してください。");
  }
  if (Object.keys(input).some((key) => !allowed.has(key))) {
    throw new HttpError(400, "invalid_request", "未対応の入力項目が含まれています。");
  }
}

function methodNotAllowed(methods: string[]): never {
  throw new HttpError(405, "method_not_allowed", `使用できるメソッドは ${methods.join(", ")} です。`);
}

function clientIp(request: Request): string {
  return (request.headers.get("cf-connecting-ip") ?? "unknown").slice(0, 128);
}

function generatedSlug(): string {
  const date = new Date().toISOString().slice(0, 10).replaceAll("-", "");
  return `news-${date}-${randomId().slice(0, 8)}`;
}

function authenticatedHeaders(sessionToken: string, csrfToken: string): Headers {
  const headers = adminHeaders();
  headers.append("set-cookie", sessionCookie(sessionToken));
  headers.append("set-cookie", csrfCookie(csrfToken));
  return headers;
}

function clearedAuthenticationHeaders(): Headers {
  const headers = adminHeaders();
  headers.append("set-cookie", expiredCookie());
  headers.append("set-cookie", expiredCsrfCookie());
  return headers;
}

function normalizeOptionalText(value: unknown, label: string, max: number): string {
  if (value === undefined || value === null || value === "") return "";
  return requireText(value, label, 1, max);
}

function safeMediaId(value: unknown, preserve: string | null): string | null {
  if (value === undefined) return preserve;
  if (value === null || value === "") return null;
  if (typeof value !== "string" || !UUID_PATTERN.test(value)) {
    throw new HttpError(400, "invalid_image", "アイキャッチ画像を確認してください。");
  }
  return value;
}

function parseActions(value: unknown): ParsedAction[] {
  if (!Array.isArray(value) || value.length > 5) {
    throw new HttpError(400, "invalid_request", "操作ボタンを確認してください。");
  }
  return value.map((raw, sortOrder) => {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
      throw new HttpError(400, "invalid_request", "操作ボタンを確認してください。");
    }
    const input = raw as Record<string, unknown>;
    assertKeys(input, new Set(["label", "url", "behavior", "style"]));
    const behavior = String(input.behavior ?? "same_tab");
    const style = String(input.style ?? "primary");
    if (!["same_tab", "new_tab", "download"].includes(behavior) || !["primary", "secondary"].includes(style)) {
      throw new HttpError(400, "invalid_request", "操作ボタンを確認してください。");
    }
    return {
      id: randomId(),
      label: requireText(input.label, "ボタン名", 1, 80),
      url: safeActionUrl(input.url),
      behavior,
      style,
      sortOrder,
    };
  });
}

function parseArticle(input: Record<string, unknown>, existing: ArticleRow | null): ParsedArticle {
  assertKeys(input, ARTICLE_INPUT_KEYS);
  const legacy = existing?.content_kind === "legacy_link";
  if (!existing && input.contentKind && input.contentKind !== "article") {
    throw new HttpError(400, "invalid_content_kind", "本文なしのお知らせは新規作成できません。");
  }
  if (existing && input.contentKind && input.contentKind !== existing.content_kind) {
    throw new HttpError(400, "invalid_content_kind", "お知らせの種類は変更できません。");
  }
  const slug = input.slug === undefined
    ? (existing?.slug ?? generatedSlug())
    : validateSlug(input.slug);
  const title = requireText(input.title, "タイトル", 1, 160);
  const subtitle = normalizeOptionalText(input.subtitle, "サブタイトル", 240);
  const summary = requireText(input.summary, "説明", 1, 500);
  const category = requireText(input.category, "カテゴリー", 1, 80);
  const coverAlt = requireText(input.coverAlt, "画像の説明", 1, 300);
  const coverMediaId = safeMediaId(input.coverMediaId, existing?.cover_media_id ?? null);
  if (input.markdownAutoConvert !== undefined && typeof input.markdownAutoConvert !== "boolean") {
    throw new HttpError(400, "invalid_request", "Markdown自動変換の設定を確認してください。");
  }
  const markdownAutoConvert = input.markdownAutoConvert === undefined
    ? Number(existing?.markdown_auto_convert ?? 1)
    : input.markdownAutoConvert ? 1 : 0;

  if (legacy) {
    return {
      slug, title, subtitle, summary, category, coverAlt, coverMediaId,
      bodySource: null, bodyFormat: "none", bodyHtml: null, markdownAutoConvert: 0,
      actions: parseActions(input.actions),
    };
  }

  if (input.bodyFormat !== undefined && input.bodyFormat !== "markdown" && input.bodyFormat !== "html") {
    throw new HttpError(400, "invalid_request", "本文形式を確認してください。");
  }
  const bodyFormat = input.bodyFormat === "markdown" ? "markdown" : "html";
  const bodySource = bodyFormat === "markdown"
    ? requireText(input.bodySource, "本文", 1, BODY_SOURCE_MAX)
    : requireText(input.bodyHtml, "本文", 1, BODY_SOURCE_MAX);
  const bodyHtml = renderBody(bodySource, bodyFormat);
  if (!bodyHtml.replace(/<[^>]*>/g, "").trim() && !bodyHtml.includes("<img ")) {
    throw new HttpError(400, "invalid_request", "本文を入力してください。");
  }
  return {
    slug, title, subtitle, summary, category, coverAlt, coverMediaId,
    bodySource, bodyFormat, bodyHtml, markdownAutoConvert, actions: [],
  };
}

function publicAction(row: Record<string, unknown>): Record<string, unknown> | null {
    const url = safeActionUrlForRead(row.url);
    if (!url) return null;
    return {
      label: String(row.label), url, behavior: String(row.behavior), style: String(row.style),
    };
}

async function actionRows(env: Env, articleId: string): Promise<Array<Record<string, unknown>>> {
  const rows = (await env.CMS_DB.prepare(
    "SELECT label, url, behavior, style FROM cms_article_actions WHERE article_id = ? ORDER BY sort_order, id",
  ).bind(articleId).all<Record<string, unknown>>()).results;
  return rows.flatMap((row) => {
    const action = publicAction(row);
    return action ? [action] : [];
  });
}

async function actionsForArticles(env: Env, articleIds: string[]): Promise<Map<string, Array<Record<string, unknown>>>> {
  const result = new Map<string, Array<Record<string, unknown>>>();
  if (!articleIds.length) return result;
  const placeholders = articleIds.map(() => "?").join(", ");
  const rows = (await env.CMS_DB.prepare(
    `SELECT article_id, label, url, behavior, style FROM cms_article_actions
     WHERE article_id IN (${placeholders}) ORDER BY article_id, sort_order, id`,
  ).bind(...articleIds).all<Record<string, unknown>>()).results;
  for (const row of rows) {
    const action = publicAction(row);
    if (!action) continue;
    const articleId = String(row.article_id);
    const actions = result.get(articleId) ?? [];
    actions.push(action);
    result.set(articleId, actions);
  }
  return result;
}

function coverUrl(row: ArticleRow): string {
  if (row.cover_media_id) return `/api/media/${row.cover_media_id}`;
  return safeLegacyCoverPath(row.legacy_cover_path);
}

async function articleCard(
  env: Env,
  row: ArticleRow,
  prefetchedActions?: Array<Record<string, unknown>>,
): Promise<Record<string, unknown>> {
  return {
    id: row.id,
    slug: row.slug,
    contentKind: row.content_kind,
    title: row.title,
    subtitle: row.subtitle,
    summary: row.summary,
    category: row.category,
    coverUrl: coverUrl(row),
    coverAlt: row.cover_alt,
    publishedAt: row.published_at,
    detailUrl: row.content_kind === "article" ? `/news/${row.slug}` : null,
    actions: prefetchedActions ?? await actionRows(env, row.id),
  };
}

async function adminArticle(
  env: Env,
  row: ArticleRow,
  prefetchedActions?: Array<Record<string, unknown>>,
): Promise<Record<string, unknown>> {
  return {
    ...(await articleCard(env, row, prefetchedActions)),
    bodySource: row.body_source,
    bodyFormat: row.body_format,
    bodyHtml: row.body_html,
    coverMediaId: row.cover_media_id,
    status: row.status,
    createdBy: row.created_by,
    authorName: row.author_name_snapshot,
    authorJobTitle: row.author_job_title_snapshot,
    author: { realName: row.author_name_snapshot, jobTitle: row.author_job_title_snapshot },
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    unpublishedAt: row.unpublished_at,
    deletedAt: row.deleted_at,
    version: Number(row.version),
    markdownAutoConvert: Boolean(row.markdown_auto_convert),
  };
}

async function getArticle(env: Env, id: string): Promise<ArticleRow | null> {
  return env.CMS_DB.prepare(`SELECT ${ARTICLE_COLUMNS} FROM cms_articles WHERE id = ?`).bind(id).first<ArticleRow>();
}

async function ownedArticle(env: Env, actor: Actor, id: string): Promise<ArticleRow> {
  const query = `SELECT ${ARTICLE_COLUMNS} FROM cms_articles WHERE id = ? ${actor.user.role === "reporter" ? "AND created_by = ?" : ""}`;
  const row = await env.CMS_DB.prepare(query)
    .bind(...(actor.user.role === "reporter" ? [id, actor.user.id] : [id]))
    .first<ArticleRow>();
  if (!row) throw new HttpError(404, "not_found", "対象が見つかりません。");
  return row;
}

function bodyMediaIds(html: string | null): string[] {
  if (!html) return [];
  return [...new Set([...html.matchAll(/\/api\/media\/([0-9a-f-]{36})/gi)].map((match) => match[1]!))].slice(0, 30);
}

async function validateMediaAccess(env: Env, actor: Actor, ids: Array<string | null>): Promise<void> {
  const uniqueIds = [...new Set(ids.filter((value): value is string => Boolean(value)))];
  if (!uniqueIds.length) return;
  if (uniqueIds.some((id) => !UUID_PATTERN.test(id))) throw new HttpError(400, "invalid_image", "画像を確認してください。");
  const placeholders = uniqueIds.map(() => "?").join(", ");
  const rows = (await env.CMS_DB.prepare(
    `SELECT id FROM cms_media WHERE id IN (${placeholders}) AND deleted_at IS NULL
     ${actor.user.role === "reporter" ? "AND owner_user_id = ?" : ""}`,
  ).bind(...uniqueIds, ...(actor.user.role === "reporter" ? [actor.user.id] : [])).all<{ id: string }>()).results;
  if (rows.length !== uniqueIds.length) throw new HttpError(400, "invalid_image", "画像を確認してください。");
}

function snapshot(article: Record<string, unknown>): string {
  const value = JSON.stringify(article);
  if (value.length > 180_000) throw new HttpError(400, "body_too_large", "記事が長すぎます。");
  return value;
}

function revisionStatement(
  env: Env,
  articleId: string,
  version: number,
  mutationId: string,
  value: string,
  actorId: string,
): D1PreparedStatement {
  return env.CMS_DB.prepare(
    `INSERT INTO cms_article_revisions (id, article_id, article_version, snapshot_json, created_by)
     SELECT ?, id, ?, ?, ? FROM cms_articles WHERE id = ? AND version = ? AND mutation_id = ?`,
  ).bind(randomId(), version, value, actorId, articleId, version, mutationId);
}

function pruneRevisionStatement(env: Env, articleId: string, mutationId: string): D1PreparedStatement {
  return env.CMS_DB.prepare(
    `DELETE FROM cms_article_revisions
     WHERE article_id = ? AND article_version NOT IN (
       SELECT article_version FROM cms_article_revisions WHERE article_id = ? ORDER BY article_version DESC LIMIT 50
     ) AND EXISTS (SELECT 1 FROM cms_articles WHERE id = ? AND mutation_id = ?)`,
  ).bind(articleId, articleId, articleId, mutationId);
}

function bodyMediaStatements(env: Env, articleId: string, ids: string[], version: number, mutationId: string): D1PreparedStatement[] {
  const statements: D1PreparedStatement[] = [
    env.CMS_DB.prepare(
      `DELETE FROM cms_article_media
       WHERE article_id = ? AND placement = 'body'
         AND EXISTS (SELECT 1 FROM cms_articles WHERE id = ? AND version = ? AND mutation_id = ?)`,
    ).bind(articleId, articleId, version, mutationId),
  ];
  ids.forEach((mediaId, sortOrder) => {
    statements.push(env.CMS_DB.prepare(
      `INSERT INTO cms_article_media (article_id, media_id, placement, alt_text, caption, sort_order)
       SELECT ?, ?, 'body', '本文中の画像', '', ?
       WHERE EXISTS (SELECT 1 FROM cms_articles WHERE id = ? AND version = ? AND mutation_id = ?)`,
    ).bind(articleId, mediaId, sortOrder, articleId, version, mutationId));
  });
  return statements;
}

function actionStatements(env: Env, articleId: string, actions: ParsedAction[], version: number, mutationId: string): D1PreparedStatement[] {
  const statements: D1PreparedStatement[] = [
    env.CMS_DB.prepare(
      `DELETE FROM cms_article_actions
       WHERE article_id = ? AND EXISTS (SELECT 1 FROM cms_articles WHERE id = ? AND version = ? AND mutation_id = ?)`,
    ).bind(articleId, articleId, version, mutationId),
  ];
  actions.forEach((action) => {
    statements.push(env.CMS_DB.prepare(
      `INSERT INTO cms_article_actions (id, article_id, label, url, behavior, style, sort_order)
       SELECT ?, ?, ?, ?, ?, ?, ?
       WHERE EXISTS (SELECT 1 FROM cms_articles WHERE id = ? AND version = ? AND mutation_id = ?)`,
    ).bind(action.id, articleId, action.label, action.url, action.behavior, action.style, action.sortOrder, articleId, version, mutationId));
  });
  return statements;
}

function auditStatement(
  env: Env,
  requestId: string,
  actor: Actor | null,
  action: string,
  targetType: string,
  targetId: string | null,
  conditionArticle?: { id: string; version: number; mutationId?: string },
): D1PreparedStatement {
  const base = `INSERT INTO cms_audit_logs
    (id, request_id, actor_user_id, actor_role, action, target_type, target_id, outcome, details_json)`;
  if (conditionArticle) {
    const mutationCondition = conditionArticle.mutationId ? " AND mutation_id = ?" : "";
    return env.CMS_DB.prepare(
      `${base}
       SELECT ?, ?, ?, ?, ?, ?, ?, 'success', '{}'
       WHERE EXISTS (SELECT 1 FROM cms_articles WHERE id = ? AND version = ?${mutationCondition})`,
    ).bind(
      randomId(), requestId, actor?.user.id ?? null, actor?.user.role ?? null,
      action, targetType, targetId, conditionArticle.id, conditionArticle.version,
      ...(conditionArticle.mutationId ? [conditionArticle.mutationId] : []),
    );
  }
  return env.CMS_DB.prepare(`${base} VALUES (?, ?, ?, ?, ?, ?, ?, 'success', '{}')`).bind(
    randomId(), requestId, actor?.user.id ?? null, actor?.user.role ?? null, action, targetType, targetId,
  );
}

function auditIfSessionStatement(
  env: Env,
  requestId: string,
  actor: Actor | null,
  action: string,
  targetType: string,
  targetId: string | null,
  sessionTokenHash: string,
): D1PreparedStatement {
  return env.CMS_DB.prepare(
    `INSERT INTO cms_audit_logs
       (id, request_id, actor_user_id, actor_role, action, target_type, target_id, outcome, details_json)
     SELECT ?, ?, ?, ?, ?, ?, ?, 'success', '{}'
     WHERE EXISTS (SELECT 1 FROM cms_sessions WHERE token_hash = ?)`,
  ).bind(
    randomId(), requestId, actor?.user.id ?? null, actor?.user.role ?? null,
    action, targetType, targetId, sessionTokenHash,
  );
}

function auditIfUserMutationStatement(
  env: Env,
  requestId: string,
  actor: Actor,
  action: string,
  userId: string,
  mutationId: string,
  details: Record<string, unknown>,
): D1PreparedStatement {
  return env.CMS_DB.prepare(
    `INSERT INTO cms_audit_logs
       (id, request_id, actor_user_id, actor_role, action, target_type, target_id, outcome, details_json)
     SELECT ?, ?, ?, ?, ?, 'user', ?, 'success', ?
     WHERE EXISTS (SELECT 1 FROM cms_users WHERE id = ? AND mutation_id = ?)`,
  ).bind(
    randomId(), requestId, actor.user.id, actor.user.role, action, userId,
    JSON.stringify(details), userId, mutationId,
  );
}

function auditIfMediaStatement(
  env: Env,
  requestId: string,
  actor: Actor,
  action: string,
  mediaId: string,
  requireUnreferenced = false,
): D1PreparedStatement {
  const ownerCondition = actor.user.role === "reporter" ? " AND m.owner_user_id = ?" : "";
  const referenceCondition = requireUnreferenced
    ? ` AND NOT EXISTS (SELECT 1 FROM cms_articles a WHERE a.cover_media_id = m.id)
        AND NOT EXISTS (SELECT 1 FROM cms_article_media am WHERE am.media_id = m.id)`
    : "";
  return env.CMS_DB.prepare(
    `INSERT INTO cms_audit_logs
       (id, request_id, actor_user_id, actor_role, action, target_type, target_id, outcome, details_json)
     SELECT ?, ?, ?, ?, ?, 'media', ?, 'success', '{}'
     WHERE EXISTS (
       SELECT 1 FROM cms_media m WHERE m.id = ? AND m.deleted_at IS NULL${ownerCondition}${referenceCondition}
     )`,
  ).bind(
    randomId(), requestId, actor.user.id, actor.user.role, action, mediaId, mediaId,
    ...(actor.user.role === "reporter" ? [actor.user.id] : []),
  );
}

async function consumeRate(
  env: Env,
  scopes: string[],
  maximum: number,
  windowMs: number,
  lockMs: number,
): Promise<void> {
  const timestamp = now();
  const expiredWindow = new Date(Date.now() - windowMs).toISOString();
  const lockedUntil = new Date(Date.now() + lockMs).toISOString();
  const retentionCutoff = new Date(Date.now() - 24 * 60 * 60_000).toISOString();
  for (const scope of scopes) {
    const state = await env.CMS_DB.prepare("SELECT locked_until FROM cms_login_attempts WHERE scope_hash = ?")
      .bind(scope).first<{ locked_until: string | null }>();
    if (state?.locked_until && state.locked_until > timestamp) {
      throw new HttpError(429, "rate_limited", "しばらくしてから再度お試しください。");
    }
  }
  const statements = scopes.map((scope) => env.CMS_DB.prepare(
    `INSERT INTO cms_login_attempts (scope_hash, failure_count, window_started_at, locked_until, updated_at)
     VALUES (?, 1, ?, NULL, ?)
     ON CONFLICT(scope_hash) DO UPDATE SET
       failure_count = CASE WHEN cms_login_attempts.window_started_at <= ? THEN 1 ELSE cms_login_attempts.failure_count + 1 END,
       window_started_at = CASE WHEN cms_login_attempts.window_started_at <= ? THEN excluded.window_started_at ELSE cms_login_attempts.window_started_at END,
       locked_until = CASE
         WHEN cms_login_attempts.window_started_at <= ? THEN NULL
         WHEN cms_login_attempts.failure_count + 1 > ? THEN ?
         ELSE cms_login_attempts.locked_until
       END,
       updated_at = excluded.updated_at`,
  ).bind(scope, timestamp, timestamp, expiredWindow, expiredWindow, expiredWindow, maximum, lockedUntil));
  statements.push(env.CMS_DB.prepare(
    `DELETE FROM cms_login_attempts
     WHERE scope_hash IN (
       SELECT scope_hash FROM cms_login_attempts
       WHERE updated_at < ?
       ORDER BY updated_at ASC
       LIMIT 32
     )`,
  ).bind(retentionCutoff));
  await env.CMS_DB.batch(statements);
  for (const scope of scopes) {
    const state = await env.CMS_DB.prepare("SELECT locked_until FROM cms_login_attempts WHERE scope_hash = ?")
      .bind(scope).first<{ locked_until: string | null }>();
    if (state?.locked_until && state.locked_until > timestamp) {
      throw new HttpError(429, "rate_limited", "しばらくしてから再度お試しください。");
    }
  }
}

async function authScopes(env: Env, request: Request, loginId: string, kind: string): Promise<string[]> {
  return Promise.all([
    privateScopeHash(env, `${kind}-ip`, clientIp(request)),
    privateScopeHash(env, `${kind}-account`, loginId),
  ]);
}

async function setupStatus(ctx: Ctx): Promise<Response> {
  if (ctx.request.method !== "GET" && ctx.request.method !== "HEAD") methodNotAllowed(["GET", "HEAD"]);
  const owner = await ctx.env.CMS_DB.prepare("SELECT id FROM cms_users WHERE is_fixed_owner = 1 LIMIT 1").first();
  if (ctx.request.method === "HEAD") return new Response(null, { headers: adminHeaders() });
  return json({ required: !owner }, { headers: adminHeaders() });
}

async function setup(ctx: Ctx, requestId: string): Promise<Response> {
  if (ctx.request.method !== "POST") methodNotAllowed(["POST"]);
  originGuard(ctx.request);
  const existing = await ctx.env.CMS_DB.prepare("SELECT id FROM cms_users WHERE is_fixed_owner = 1 LIMIT 1").first();
  if (existing) throw new HttpError(409, "already_configured", "初期設定は完了しています。");
  await consumeRate(
    ctx.env,
    [await privateScopeHash(ctx.env, "setup-ip", clientIp(ctx.request))],
    10,
    60 * 60_000,
    60 * 60_000,
  );
  const input = await body<Record<string, unknown>>(ctx.request);
  assertKeys(input, new Set([
    "bootstrapToken", "loginId", "realName", "jobTitle",
    "passwordVerifier", "passwordSalt", "passwordIterations",
  ]));
  const token = requireText(input.bootstrapToken, "セットアップトークン", 32, 512);
  if (!ctx.env.CMS_BOOTSTRAP_TOKEN || !constantTimeEqual(await sha256(token), await sha256(ctx.env.CMS_BOOTSTRAP_TOKEN))) {
    throw new HttpError(403, "setup_rejected", "初期設定を実行できません。");
  }
  const credential = validateClientCredential(input.passwordVerifier, input.passwordSalt, input.passwordIterations);
  const id = randomId();
  const timestamp = now();
  const protectedHash = await protectVerifier(ctx.env, credential.verifier);
  try {
    await ctx.env.CMS_DB.batch([
      ctx.env.CMS_DB.prepare(
        `INSERT INTO cms_users
           (id, login_id, real_name, job_title, role, status, is_fixed_owner,
            password_hash, password_salt, password_algorithm, password_iterations,
            password_changed_at, force_password_change)
         VALUES (?, ?, ?, ?, 'owner', 'active', 1, ?, ?, ?, ?, ?, 0)`,
      ).bind(
        id, normalizeLogin(input.loginId), requireText(input.realName, "氏名", 1, 100),
        requireText(input.jobTitle, "役職", 1, 100), protectedHash, credential.salt,
        PASSWORD_ALGORITHM, PASSWORD_ITERATIONS, timestamp,
      ),
      auditStatement(ctx.env, requestId, null, "owner.setup", "user", id),
    ]);
  } catch {
    throw new HttpError(409, "already_configured", "初期設定は完了しているか、入力内容が重複しています。");
  }
  return json({ created: true }, { status: 201, headers: adminHeaders() });
}

async function challenge(ctx: Ctx): Promise<Response> {
  originGuard(ctx.request);
  const input = await body<Record<string, unknown>>(ctx.request);
  assertKeys(input, new Set(["loginId"]));
  const loginId = normalizeLogin(input.loginId);
  await consumeRate(ctx.env, await authScopes(ctx.env, ctx.request, loginId, "challenge"), 60, 15 * 60_000, 15 * 60_000);
  const user = await ctx.env.CMS_DB.prepare(
    "SELECT password_salt, password_algorithm, password_iterations, status FROM cms_users WHERE login_id = ?",
  ).bind(loginId).first<Record<string, unknown>>();
  const fallbackSalt = await fakePasswordSalt(ctx.env, loginId);
  const valid = user?.status === "active"
    && user.password_algorithm === PASSWORD_ALGORITHM
    && Number(user.password_iterations) === PASSWORD_ITERATIONS
    && typeof user.password_salt === "string"
    && /^[A-Za-z0-9_-]{43}$/.test(user.password_salt);
  const salt = valid ? String(user!.password_salt) : fallbackSalt;
  return json({ salt, iterations: PASSWORD_ITERATIONS, algorithm: PASSWORD_ALGORITHM }, { headers: adminHeaders() });
}

async function login(ctx: Ctx, requestId: string): Promise<Response> {
  originGuard(ctx.request);
  const input = await body<Record<string, unknown>>(ctx.request);
  assertKeys(input, new Set(["loginId", "passwordVerifier"]));
  const loginId = normalizeLogin(input.loginId);
  const verifier = validateLoginVerifier(input.passwordVerifier);
  const scopes = await authScopes(ctx.env, ctx.request, loginId, "login");
  // Reserve one attempt before checking the credential. A successful request
  // later decrements the reservation without erasing concurrent failures.
  await consumeRate(ctx.env, scopes, 8, 15 * 60_000, 15 * 60_000);

  const user = await ctx.env.CMS_DB.prepare("SELECT * FROM cms_users WHERE login_id = ?")
    .bind(loginId).first<User>();
  const verification = await verifyProtectedVerifier(ctx.env, verifier, user?.password_hash ?? null);
  const valid = Boolean(
    user
    && user.status === "active"
    && user.password_algorithm === PASSWORD_ALGORITHM
    && user.password_iterations === PASSWORD_ITERATIONS
    && user.password_salt
    && verification.ok,
  );
  if (!valid) {
    throw new HttpError(401, "invalid_credentials", "IDまたはパスワードが正しくありません。");
  }

  const token = secret();
  const tokenHash = await sha256(token);
  const csrf = secret();
  const csrfHash = await sha256(csrf);
  const timestamp = now();
  const absolute = new Date(Date.now() + SESSION_ABSOLUTE_MS).toISOString();
  const idle = new Date(Date.now() + SESSION_IDLE_MS).toISOString();
  const statements: D1PreparedStatement[] = [
    ctx.env.CMS_DB.prepare(
      `INSERT INTO cms_sessions
         (token_hash, user_id, csrf_token_hash, created_at, last_seen_at, idle_expires_at,
          absolute_expires_at, ip_hash, user_agent_hash)
       SELECT ?, u.id, ?, ?, ?, ?, ?, ?, ?
       FROM cms_users u
       WHERE u.id = ? AND u.status = 'active' AND u.version = ? AND u.password_hash = ?
         AND u.password_algorithm = ? AND u.password_iterations = ?
         AND NOT EXISTS (
           SELECT 1 FROM cms_login_attempts
           WHERE scope_hash IN (?, ?) AND locked_until IS NOT NULL AND locked_until > ?
         )`,
    ).bind(
      tokenHash, csrfHash, timestamp, timestamp, idle, absolute,
      await privateScopeHash(ctx.env, "session-ip", clientIp(ctx.request)),
      await sha256(ctx.request.headers.get("user-agent") ?? ""),
      user!.id, user!.version, user!.password_hash, PASSWORD_ALGORITHM, PASSWORD_ITERATIONS,
      scopes[0], scopes[1], timestamp,
    ),
  ];
  if (verification.usedPrevious) {
    statements.push(ctx.env.CMS_DB.prepare(
      `UPDATE cms_users SET password_hash = ?, password_changed_at = ?, updated_at = ?, version = version + 1
       WHERE id = ? AND version = ? AND EXISTS (SELECT 1 FROM cms_sessions WHERE token_hash = ?)`,
    ).bind(await protectVerifier(ctx.env, verifier), timestamp, timestamp, user!.id, user!.version, tokenHash));
  }
  statements.push(
    ctx.env.CMS_DB.prepare(
      `UPDATE cms_login_attempts SET
         failure_count = CASE WHEN failure_count > 0 THEN failure_count - 1 ELSE 0 END,
         locked_until = NULL, updated_at = ?
       WHERE scope_hash IN (?, ?) AND EXISTS (SELECT 1 FROM cms_sessions WHERE token_hash = ?)`,
    ).bind(timestamp, scopes[0], scopes[1], tokenHash),
    auditIfSessionStatement(
      ctx.env, requestId, { user: user!, session: {} as never, csrf: "" },
      "auth.login", "user", user!.id, tokenHash,
    ),
  );
  const results = await ctx.env.CMS_DB.batch(statements);
  if (!results[0]?.meta.changes) {
    const blocked = await ctx.env.CMS_DB.prepare(
      `SELECT 1 AS blocked FROM cms_login_attempts
       WHERE scope_hash IN (?, ?) AND locked_until IS NOT NULL AND locked_until > ? LIMIT 1`,
    ).bind(scopes[0], scopes[1], timestamp).first();
    if (blocked) throw new HttpError(429, "rate_limited", "しばらくしてから再度お試しください。");
    throw new HttpError(401, "invalid_credentials", "IDまたはパスワードが正しくありません。");
  }
  if (verification.usedPrevious) user!.version += 1;
  return json({ user: publicUser(user!), csrfToken: csrf }, {
    headers: authenticatedHeaders(token, csrf),
  });
}

async function changePassword(ctx: Ctx, requestId: string): Promise<Response> {
  originGuard(ctx.request);
  const actor = await actorFor(ctx.request, ctx.env, true);
  const input = await body<Record<string, unknown>>(ctx.request);
  assertKeys(input, new Set([
    "currentPasswordVerifier", "newPasswordVerifier", "newPasswordSalt", "newPasswordIterations",
  ]));
  const currentVerifier = validateLoginVerifier(input.currentPasswordVerifier);
  const nextCredential = validateClientCredential(
    input.newPasswordVerifier,
    input.newPasswordSalt,
    input.newPasswordIterations,
  );
  const scopes = await authScopes(ctx.env, ctx.request, actor.user.login_id, "password-change");
  await consumeRate(ctx.env, scopes, 5, 60 * 60_000, 60 * 60_000);
  const currentVerification = await verifyProtectedVerifier(ctx.env, currentVerifier, actor.user.password_hash);
  if (!currentVerification.ok) {
    throw new HttpError(401, "invalid_credentials", "現在のパスワードが正しくありません。");
  }

  const timestamp = now();
  const nextHash = await protectVerifier(ctx.env, nextCredential.verifier);
  const nextVersion = Number(actor.user.version) + 1;
  const results = await ctx.env.CMS_DB.batch([
    ctx.env.CMS_DB.prepare(
      `UPDATE cms_users SET
         password_hash = ?, password_salt = ?, password_algorithm = ?, password_iterations = ?,
         password_changed_at = ?, force_password_change = 0, updated_at = ?, mutation_id = ?,
         version = version + 1
       WHERE id = ? AND version = ? AND status = 'active' AND password_hash = ?
         AND password_algorithm = ? AND password_iterations = ?`,
    ).bind(
      nextHash, nextCredential.salt, PASSWORD_ALGORITHM, PASSWORD_ITERATIONS,
      timestamp, timestamp, requestId, actor.user.id, actor.user.version,
      actor.user.password_hash, actor.user.password_algorithm, actor.user.password_iterations,
    ),
    ctx.env.CMS_DB.prepare(
      `DELETE FROM cms_sessions WHERE user_id = ?
       AND EXISTS (SELECT 1 FROM cms_users WHERE id = ? AND version = ? AND mutation_id = ?)`,
    ).bind(actor.user.id, actor.user.id, nextVersion, requestId),
    ctx.env.CMS_DB.prepare(
      `UPDATE cms_user_tokens SET used_at = ? WHERE user_id = ? AND used_at IS NULL
       AND EXISTS (SELECT 1 FROM cms_users WHERE id = ? AND version = ? AND mutation_id = ?)`,
    ).bind(timestamp, actor.user.id, actor.user.id, nextVersion, requestId),
    ctx.env.CMS_DB.prepare(
      `UPDATE cms_login_attempts SET
         failure_count = CASE WHEN failure_count > 0 THEN failure_count - 1 ELSE 0 END,
         locked_until = NULL, updated_at = ?
       WHERE scope_hash IN (?, ?)
         AND EXISTS (SELECT 1 FROM cms_users WHERE id = ? AND version = ? AND mutation_id = ?)`,
    ).bind(timestamp, scopes[0], scopes[1], actor.user.id, nextVersion, requestId),
    auditIfUserMutationStatement(
      ctx.env, requestId, actor, "auth.change_password", actor.user.id, requestId,
      { beforeVersion: actor.user.version, afterVersion: nextVersion },
    ),
  ]);
  if (!results[0]?.meta.changes) {
    throw new HttpError(409, "stale_write", "認証情報が更新されています。再度ログインしてください。");
  }
  return json({ changed: true }, { headers: clearedAuthenticationHeaders() });
}

async function activation(ctx: Ctx, requestId: string): Promise<Response> {
  originGuard(ctx.request);
  const input = await body<Record<string, unknown>>(ctx.request);
  assertKeys(input, new Set(["token", "passwordVerifier", "passwordSalt", "passwordIterations"]));
  const token = requireText(input.token, "トークン", 32, 512);
  const credential = validateClientCredential(input.passwordVerifier, input.passwordSalt, input.passwordIterations);
  const tokenHash = await sha256(token);
  await consumeRate(
    ctx.env,
    [
      await privateScopeHash(ctx.env, "activation-ip", clientIp(ctx.request)),
      await privateScopeHash(ctx.env, "activation-token", tokenHash),
    ],
    10,
    60 * 60_000,
    60 * 60_000,
  );
  const lookupTime = now();
  const row = await ctx.env.CMS_DB.prepare(
    `SELECT t.token_hash, t.user_id, t.purpose FROM cms_user_tokens t
     JOIN cms_users u ON u.id = t.user_id
     WHERE t.token_hash = ? AND t.used_at IS NULL AND t.expires_at > ?
       AND u.is_fixed_owner = 0
       AND (
         (t.purpose = 'activate' AND u.status = 'pending')
         OR (t.purpose = 'reset_password' AND u.status IN ('active', 'disabled'))
       )`,
  ).bind(tokenHash, lookupTime).first<{ token_hash: string; user_id: string; purpose: "activate" | "reset_password" }>();
  if (!row) throw new HttpError(400, "invalid_token", "このリンクは使用できません。");
  const timestamp = now();
  const protectedHash = await protectVerifier(ctx.env, credential.verifier);
  const claimedHash = await sha256(`${tokenHash}\0${requestId}`);
  const results = await ctx.env.CMS_DB.batch([
    ctx.env.CMS_DB.prepare(
      `UPDATE cms_user_tokens AS t SET token_hash = ?, used_at = ?
       WHERE t.token_hash = ? AND t.used_at IS NULL AND t.expires_at > ? AND t.purpose = ?
         AND EXISTS (
           SELECT 1 FROM cms_users u WHERE u.id = t.user_id AND u.is_fixed_owner = 0
             AND (
               (t.purpose = 'activate' AND u.status = 'pending')
               OR (t.purpose = 'reset_password' AND u.status IN ('active', 'disabled'))
             )
         )`,
    ).bind(claimedHash, timestamp, tokenHash, timestamp, row.purpose),
    ctx.env.CMS_DB.prepare(
      `UPDATE cms_users SET
         password_hash = ?, password_salt = ?, password_algorithm = ?, password_iterations = ?,
         password_changed_at = ?, status = CASE WHEN ? = 'activate' THEN 'active' ELSE status END,
         force_password_change = 0,
         updated_at = ?, version = version + 1
       WHERE id = ? AND is_fixed_owner = 0
         AND ((? = 'activate' AND status = 'pending') OR (? = 'reset_password' AND status IN ('active', 'disabled')))
         AND EXISTS (SELECT 1 FROM cms_user_tokens WHERE token_hash = ? AND used_at = ?)`,
    ).bind(
      protectedHash, credential.salt, PASSWORD_ALGORITHM, PASSWORD_ITERATIONS,
      timestamp, row.purpose, timestamp, row.user_id, row.purpose, row.purpose, claimedHash, timestamp,
    ),
    ctx.env.CMS_DB.prepare(
      `DELETE FROM cms_sessions WHERE user_id = ?
       AND EXISTS (SELECT 1 FROM cms_user_tokens WHERE token_hash = ? AND used_at = ?)
       AND EXISTS (SELECT 1 FROM cms_users WHERE id = ? AND password_hash = ? AND password_changed_at = ?)`,
    ).bind(row.user_id, claimedHash, timestamp, row.user_id, protectedHash, timestamp),
    ctx.env.CMS_DB.prepare(
      `UPDATE cms_user_tokens SET used_at = ?
       WHERE user_id = ? AND token_hash <> ? AND used_at IS NULL
         AND EXISTS (SELECT 1 FROM cms_users WHERE id = ? AND password_hash = ? AND password_changed_at = ?)`,
    ).bind(timestamp, row.user_id, claimedHash, row.user_id, protectedHash, timestamp),
    ctx.env.CMS_DB.prepare(
      `INSERT INTO cms_audit_logs
         (id, request_id, actor_user_id, actor_role, action, target_type, target_id, outcome, details_json)
       SELECT ?, ?, NULL, NULL, ?, 'user', ?, 'success', '{}'
       WHERE EXISTS (SELECT 1 FROM cms_user_tokens WHERE token_hash = ? AND used_at = ?)
         AND EXISTS (SELECT 1 FROM cms_users WHERE id = ? AND password_hash = ? AND password_changed_at = ?)`,
    ).bind(
      randomId(), requestId, `user.${row.purpose}`, row.user_id, claimedHash, timestamp,
      row.user_id, protectedHash, timestamp,
    ),
  ]);
  if (!results[0]?.meta.changes || !results[1]?.meta.changes) {
    throw new HttpError(400, "invalid_token", "このリンクは使用できません。");
  }
  return json({ activated: true }, { headers: adminHeaders() });
}

async function publicArticles(ctx: Ctx, slug?: string): Promise<Response> {
  if (ctx.request.method !== "GET" && ctx.request.method !== "HEAD") methodNotAllowed(["GET", "HEAD"]);
  if (slug) {
    const row = await ctx.env.CMS_DB.prepare(
      `SELECT ${ARTICLE_COLUMNS} FROM cms_articles
       WHERE slug = ? AND content_kind = 'article' AND ${PUBLIC_PREDICATE}`,
    ).bind(slug).first<ArticleRow>();
    if (!row) throw new HttpError(404, "not_found", "記事が見つかりません。");
    const related = (await ctx.env.CMS_DB.prepare(
      `SELECT ${ARTICLE_COLUMNS} FROM cms_articles
       WHERE ${PUBLIC_PREDICATE} AND id <> ?
       ORDER BY published_at DESC, display_order DESC, id LIMIT 3`,
    ).bind(row.id).all<ArticleRow>()).results;
    if (ctx.request.method === "HEAD") return new Response(null, { headers: adminHeaders() });
    const actionMap = await actionsForArticles(ctx.env, [row.id, ...related.map((item) => item.id)]);
    return json({
      article: {
        ...(await articleCard(ctx.env, row, actionMap.get(row.id) ?? [])),
        bodyHtml: row.body_html,
        author: { realName: row.author_name_snapshot, jobTitle: row.author_job_title_snapshot },
      },
      related: await Promise.all(related.map((item) => articleCard(ctx.env, item, actionMap.get(item.id) ?? []))),
    });
  }
  const url = new URL(ctx.request.url);
  const limitRaw = url.searchParams.get("limit");
  const limit = limitRaw === null ? 4 : Number(limitRaw);
  if (!Number.isInteger(limit) || limit < 1 || limit > 20) throw new HttpError(400, "invalid_limit", "件数は1〜20で指定してください。");
  const exclude = (url.searchParams.get("exclude") ?? "").slice(0, 120);
  const rows = (await ctx.env.CMS_DB.prepare(
    `SELECT ${ARTICLE_COLUMNS} FROM cms_articles
     WHERE ${PUBLIC_PREDICATE} AND id <> ?
     ORDER BY published_at DESC, display_order DESC, id LIMIT ?`,
  ).bind(exclude, limit).all<ArticleRow>()).results;
  if (ctx.request.method === "HEAD") return new Response(null, { headers: adminHeaders() });
  const actionMap = await actionsForArticles(ctx.env, rows.map((item) => item.id));
  return json({ articles: await Promise.all(rows.map((item) => articleCard(ctx.env, item, actionMap.get(item.id) ?? []))) });
}

async function articleTransition(
  ctx: Ctx,
  actor: Actor,
  row: ArticleRow,
  requestId: string,
  transition: "publish" | "unpublish" | "restore" | "soft_delete",
): Promise<Response> {
  const timestamp = now();
  const nextVersion = Number(row.version) + 1;
  let status: ArticleStatus;
  let sql: string;
  let bindings: unknown[];
  if (transition === "publish") {
    if (row.status === "deleted") throw new HttpError(409, "invalid_state", "削除済みの記事は復元してから公開してください。");
    status = "published";
    sql = `UPDATE cms_articles SET status = 'published', published_at = ?, unpublished_at = NULL,
      deleted_at = NULL, deleted_by = NULL, updated_at = ?, updated_by = ?, mutation_id = ?, version = version + 1
      WHERE id = ? AND version = ?`;
    bindings = [timestamp, timestamp, actor.user.id, requestId, row.id, row.version];
  } else if (transition === "unpublish") {
    if (row.status === "deleted") throw new HttpError(409, "invalid_state", "削除済みの記事は公開停止できません。");
    status = "unpublished";
    sql = `UPDATE cms_articles SET status = 'unpublished', unpublished_at = ?, deleted_at = NULL,
      deleted_by = NULL, updated_at = ?, updated_by = ?, mutation_id = ?, version = version + 1
      WHERE id = ? AND version = ?`;
    bindings = [timestamp, timestamp, actor.user.id, requestId, row.id, row.version];
  } else if (transition === "restore") {
    if (row.status !== "deleted") throw new HttpError(409, "invalid_state", "削除済みの記事だけ復元できます。");
    status = "unpublished";
    sql = `UPDATE cms_articles SET status = 'unpublished', unpublished_at = ?, deleted_at = NULL,
      deleted_by = NULL, updated_at = ?, updated_by = ?, mutation_id = ?, version = version + 1
      WHERE id = ? AND version = ?`;
    bindings = [timestamp, timestamp, actor.user.id, requestId, row.id, row.version];
  } else {
    if (row.status === "deleted") throw new HttpError(409, "invalid_state", "この記事はすでに削除されています。");
    status = "deleted";
    sql = `UPDATE cms_articles SET status = 'deleted', deleted_at = ?, deleted_by = ?,
      updated_at = ?, updated_by = ?, mutation_id = ?, version = version + 1
      WHERE id = ? AND version = ?`;
    bindings = [timestamp, actor.user.id, timestamp, actor.user.id, requestId, row.id, row.version];
  }
  const next = { ...row, status, version: nextVersion, updated_at: timestamp, updated_by: actor.user.id, mutation_id: requestId };
  if (transition === "publish") Object.assign(next, { published_at: timestamp, unpublished_at: null, deleted_at: null });
  if (transition === "unpublish" || transition === "restore") Object.assign(next, { unpublished_at: timestamp, deleted_at: null });
  if (transition === "soft_delete") Object.assign(next, { deleted_at: timestamp });
  const results = await ctx.env.CMS_DB.batch([
    ctx.env.CMS_DB.prepare(sql).bind(...bindings),
    revisionStatement(ctx.env, row.id, nextVersion, requestId, snapshot(next), actor.user.id),
    pruneRevisionStatement(ctx.env, row.id, requestId),
    auditStatement(ctx.env, requestId, actor, `article.${transition}`, "article", row.id, { id: row.id, version: nextVersion, mutationId: requestId }),
  ]);
  if (!results[0]?.meta.changes) throw new HttpError(409, "stale_write", "他の操作が行われました。再読み込みしてください。");
  const updated = await getArticle(ctx.env, row.id);
  if (!updated) throw new HttpError(404, "not_found", "対象が見つかりません。");
  return json({ article: await adminArticle(ctx.env, updated) }, { headers: adminHeaders() });
}

async function adminArticles(ctx: Ctx, path: string[], requestId: string): Promise<Response> {
  const write = !["GET", "HEAD"].includes(ctx.request.method);
  if (write) originGuard(ctx.request);
  const actor = await actorFor(ctx.request, ctx.env, write);
  const id = path[2];

  if (!id && (ctx.request.method === "GET" || ctx.request.method === "HEAD")) {
    const url = new URL(ctx.request.url);
    const limit = Number(url.searchParams.get("limit") ?? "20");
    const offset = Number(url.searchParams.get("offset") ?? "0");
    if (!Number.isInteger(limit) || limit < 1 || limit > 20 || !Number.isInteger(offset) || offset < 0 || offset > 100_000) {
      throw new HttpError(400, "invalid_pagination", "一覧の表示位置を確認してください。");
    }
    const query = `SELECT ${ARTICLE_COLUMNS} FROM cms_articles
      ${actor.user.role === "reporter" ? "WHERE created_by = ?" : ""}
      ORDER BY updated_at DESC, id LIMIT ? OFFSET ?`;
    const rows = (await ctx.env.CMS_DB.prepare(query)
      .bind(...(actor.user.role === "reporter" ? [actor.user.id, limit + 1, offset] : [limit + 1, offset]))
      .all<ArticleRow>()).results;
    if (ctx.request.method === "HEAD") return new Response(null, { headers: adminHeaders() });
    const hasMore = rows.length > limit;
    const page = rows.slice(0, limit);
    const actionMap = await actionsForArticles(ctx.env, page.map((row) => row.id));
    return json({
      articles: await Promise.all(page.map((row) => adminArticle(ctx.env, row, actionMap.get(row.id) ?? []))),
      hasMore,
      nextOffset: hasMore ? offset + page.length : null,
    }, { headers: adminHeaders() });
  }

  if (!id && ctx.request.method === "POST") {
    const input = await body<Record<string, unknown>>(ctx.request);
    const parsed = parseArticle(input, null);
    await validateMediaAccess(ctx.env, actor, [parsed.coverMediaId, ...bodyMediaIds(parsed.bodyHtml)]);
    const idNew = randomId();
    const timestamp = now();
    const nextRow = {
      id: idNew, slug: parsed.slug, content_kind: "article", title: parsed.title,
      subtitle: parsed.subtitle, summary: parsed.summary, category: parsed.category,
      body_source: parsed.bodySource, body_format: parsed.bodyFormat, body_html: parsed.bodyHtml,
      cover_media_id: parsed.coverMediaId, legacy_cover_path: null, cover_alt: parsed.coverAlt,
      status: "draft", created_by: actor.user.id, updated_by: actor.user.id,
      author_name_snapshot: actor.user.real_name, author_job_title_snapshot: actor.user.job_title,
      published_at: null, unpublished_at: null, deleted_at: null,
      created_at: timestamp, updated_at: timestamp, version: 1,
      markdown_auto_convert: parsed.markdownAutoConvert, mutation_id: requestId,
    };
    try {
      await ctx.env.CMS_DB.batch([
        ctx.env.CMS_DB.prepare(
          `INSERT INTO cms_articles
             (id, slug, content_kind, title, subtitle, summary, category, body_source, body_format,
              body_html, sanitizer_version, markdown_auto_convert, cover_media_id, cover_alt, status,
              created_by, updated_by, author_name_snapshot, author_job_title_snapshot,
              created_at, updated_at, version, mutation_id)
           VALUES (?, ?, 'article', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'draft', ?, ?, ?, ?, ?, ?, 1, ?)`,
        ).bind(
          idNew, parsed.slug, parsed.title, parsed.subtitle, parsed.summary, parsed.category,
          parsed.bodySource, parsed.bodyFormat, parsed.bodyHtml, SANITIZER_VERSION,
          parsed.markdownAutoConvert, parsed.coverMediaId, parsed.coverAlt, actor.user.id, actor.user.id,
          actor.user.real_name, actor.user.job_title, timestamp, timestamp, requestId,
        ),
        revisionStatement(ctx.env, idNew, 1, requestId, snapshot(nextRow), actor.user.id),
        ...bodyMediaStatements(ctx.env, idNew, bodyMediaIds(parsed.bodyHtml), 1, requestId),
        auditStatement(ctx.env, requestId, actor, "article.create", "article", idNew, { id: idNew, version: 1, mutationId: requestId }),
      ]);
    } catch {
      throw new HttpError(409, "article_conflict", "記事を保存できませんでした。もう一度お試しください。");
    }
    const created = await getArticle(ctx.env, idNew);
    if (!created) throw new HttpError(500, "internal_error", "記事を読み込めませんでした。");
    return json({ article: await adminArticle(ctx.env, created) }, { status: 201, headers: adminHeaders() });
  }

  if (!id) methodNotAllowed(["GET", "HEAD", "POST"]);
  if (!UUID_PATTERN.test(id) && !id.startsWith("art_")) throw new HttpError(404, "not_found", "対象が見つかりません。");
  const row = await ownedArticle(ctx.env, actor, id);
  const operation = path[3];

  if (operation === "publish" && ctx.request.method === "POST") return articleTransition(ctx, actor, row, requestId, "publish");
  if (operation === "unpublish" && ctx.request.method === "POST") return articleTransition(ctx, actor, row, requestId, "unpublish");
  if (operation === "restore" && ctx.request.method === "POST") return articleTransition(ctx, actor, row, requestId, "restore");
  if (operation === "permanent" && ctx.request.method === "DELETE") {
    roleAtLeast(actor, ["owner", "master"]);
    if (row.status !== "deleted") throw new HttpError(409, "invalid_state", "完全削除の前に通常の削除を行ってください。");
    const results = await ctx.env.CMS_DB.batch([
      auditStatement(ctx.env, requestId, actor, "article.permanent_delete", "article", row.id, { id: row.id, version: row.version }),
      ctx.env.CMS_DB.prepare("DELETE FROM cms_articles WHERE id = ? AND version = ? AND status = 'deleted'").bind(row.id, row.version),
    ]);
    if (!results[1]?.meta.changes) throw new HttpError(409, "stale_write", "他の操作が行われました。再読み込みしてください。");
    return json({ deleted: true }, { headers: adminHeaders() });
  }
  if (operation) methodNotAllowed(operation === "permanent" ? ["DELETE"] : ["POST"]);

  if (ctx.request.method === "GET" || ctx.request.method === "HEAD") {
    if (ctx.request.method === "HEAD") return new Response(null, { headers: adminHeaders() });
    return json({ article: await adminArticle(ctx.env, row) }, { headers: adminHeaders() });
  }
  if (ctx.request.method === "DELETE") return articleTransition(ctx, actor, row, requestId, "soft_delete");
  if (ctx.request.method !== "PATCH") methodNotAllowed(["GET", "HEAD", "PATCH", "DELETE"]);
  if (row.status === "deleted") throw new HttpError(409, "invalid_state", "削除済みの記事は復元してから編集してください。");
  const input = await body<Record<string, unknown>>(ctx.request);
  if (typeof input.version !== "number" || !Number.isInteger(input.version) || input.version < 1) {
    throw new HttpError(400, "invalid_request", "更新前のバージョンを確認してください。");
  }
  if (input.version !== Number(row.version)) {
    throw new HttpError(409, "stale_write", "他の編集内容があります。再読み込みしてください。");
  }
  const parsed = parseArticle(input, row);
  const mediaIds = bodyMediaIds(parsed.bodyHtml);
  await validateMediaAccess(ctx.env, actor, [parsed.coverMediaId, ...mediaIds]);
  const timestamp = now();
  const nextVersion = Number(row.version) + 1;
  const nextRow = {
    ...row, slug: parsed.slug, title: parsed.title, subtitle: parsed.subtitle,
    summary: parsed.summary, category: parsed.category, body_source: parsed.bodySource,
    body_format: parsed.bodyFormat, body_html: parsed.bodyHtml, cover_media_id: parsed.coverMediaId,
    cover_alt: parsed.coverAlt, markdown_auto_convert: parsed.markdownAutoConvert,
    updated_at: timestamp, updated_by: actor.user.id, version: nextVersion, mutation_id: requestId,
  };
  const statements: D1PreparedStatement[] = [
    ctx.env.CMS_DB.prepare(
      `UPDATE cms_articles SET
         slug = ?, title = ?, subtitle = ?, summary = ?, category = ?, body_source = ?,
         body_format = ?, body_html = ?, sanitizer_version = ?, markdown_auto_convert = ?,
         cover_media_id = ?, cover_alt = ?, updated_at = ?, updated_by = ?, mutation_id = ?, version = version + 1
       WHERE id = ? AND version = ?`,
    ).bind(
      parsed.slug, parsed.title, parsed.subtitle, parsed.summary, parsed.category,
      parsed.bodySource, parsed.bodyFormat, parsed.bodyHtml, SANITIZER_VERSION,
      parsed.markdownAutoConvert, parsed.coverMediaId, parsed.coverAlt, timestamp,
      actor.user.id, requestId, row.id, row.version,
    ),
    revisionStatement(ctx.env, row.id, nextVersion, requestId, snapshot(nextRow), actor.user.id),
    pruneRevisionStatement(ctx.env, row.id, requestId),
  ];
  if (row.content_kind === "legacy_link") statements.push(...actionStatements(ctx.env, row.id, parsed.actions, nextVersion, requestId));
  else statements.push(...bodyMediaStatements(ctx.env, row.id, mediaIds, nextVersion, requestId));
  statements.push(auditStatement(ctx.env, requestId, actor, "article.update", "article", row.id, { id: row.id, version: nextVersion, mutationId: requestId }));
  let results: D1Result[];
  try {
    results = await ctx.env.CMS_DB.batch(statements);
  } catch {
    throw new HttpError(409, "article_conflict", "記事を保存できませんでした。URLの重複などを確認してください。");
  }
  if (!results[0]?.meta.changes) throw new HttpError(409, "stale_write", "他の編集内容があります。再読み込みしてください。");
  const updated = await getArticle(ctx.env, row.id);
  if (!updated) throw new HttpError(404, "not_found", "対象が見つかりません。");
  return json({ article: await adminArticle(ctx.env, updated) }, { headers: adminHeaders() });
}

async function publicMedia(ctx: Ctx, id: string): Promise<Response> {
  if (ctx.request.method !== "GET" && ctx.request.method !== "HEAD") methodNotAllowed(["GET", "HEAD"]);
  if (!UUID_PATTERN.test(id)) throw new HttpError(404, "not_found", "画像が見つかりません。");
  const row = await ctx.env.CMS_DB.prepare(
    `SELECT m.id, m.owner_user_id, m.mime_type, m.sha256, m.data,
       EXISTS(
         SELECT 1 FROM cms_articles a
         LEFT JOIN cms_article_media am ON am.article_id = a.id
         WHERE (a.cover_media_id = m.id OR am.media_id = m.id)
           AND a.status = 'published' AND a.published_at IS NOT NULL AND a.deleted_at IS NULL
       ) AS is_public
     FROM cms_media m WHERE m.id = ? AND m.deleted_at IS NULL`,
  ).bind(id).first<Record<string, unknown>>();
  if (!row) throw new HttpError(404, "not_found", "画像が見つかりません。");
  if (!Number(row.is_public)) {
    const actor = await actorFor(ctx.request, ctx.env);
    if (actor.user.role === "reporter" && row.owner_user_id !== actor.user.id) {
      throw new HttpError(403, "forbidden", "この画像を表示する権限がありません。");
    }
  }
  const headers = new Headers({
    "content-type": "image/webp",
    "cache-control": "private, no-store",
    "x-content-type-options": "nosniff",
    "content-security-policy": "default-src 'none'; sandbox",
    etag: `"${String(row.sha256)}"`,
  });
  if (ctx.request.headers.get("if-none-match") === headers.get("etag")) return new Response(null, { status: 304, headers });
  return new Response(ctx.request.method === "HEAD" ? null : row.data as BodyInit, { headers });
}

async function adminMedia(ctx: Ctx, id: string | undefined, requestId: string): Promise<Response> {
  const write = ctx.request.method !== "GET" && ctx.request.method !== "HEAD";
  if (write) originGuard(ctx.request, ctx.request.method === "POST");
  const actor = await actorFor(ctx.request, ctx.env, write);
  if (!id && (ctx.request.method === "GET" || ctx.request.method === "HEAD")) {
    const url = new URL(ctx.request.url);
    const limit = Number(url.searchParams.get("limit") ?? "50");
    const offset = Number(url.searchParams.get("offset") ?? "0");
    if (!Number.isInteger(limit) || limit < 1 || limit > 50 || !Number.isInteger(offset) || offset < 0 || offset > 100_000) {
      throw new HttpError(400, "invalid_pagination", "画像一覧の表示位置を確認してください。");
    }
    const query = `SELECT id, original_name, mime_type, byte_size, width, height, sha256, created_at
      FROM cms_media WHERE deleted_at IS NULL ${actor.user.role === "reporter" ? "AND owner_user_id = ?" : ""}
      ORDER BY created_at DESC, id LIMIT ? OFFSET ?`;
    const rows = (await ctx.env.CMS_DB.prepare(query)
      .bind(...(actor.user.role === "reporter" ? [actor.user.id, limit + 1, offset] : [limit + 1, offset])).all()).results;
    if (ctx.request.method === "HEAD") return new Response(null, { headers: adminHeaders() });
    const hasMore = rows.length > limit;
    const page = rows.slice(0, limit);
    return json({ media: page, hasMore, nextOffset: hasMore ? offset + page.length : null }, { headers: adminHeaders() });
  }
  if (!id && ctx.request.method === "POST") {
    const multipartBytes = await limitedRequestBytes(ctx.request, 1_750_000);
    const form = await new Response(multipartBytes.buffer as ArrayBuffer, {
      headers: { "content-type": ctx.request.headers.get("content-type") ?? "" },
    }).formData();
    const file = form.get("image");
    if (!(file instanceof File) || file.type !== "image/webp" || file.size < 1 || file.size > 1_500_000) {
      throw new HttpError(400, "invalid_image", "WebP画像は1.5MB以下にしてください。");
    }
    const bytes = new Uint8Array(await file.arrayBuffer());
    const dimensions = webpDimensions(bytes);
    if (!dimensions) throw new HttpError(400, "invalid_image", "有効なWebP画像を指定してください。");
    const declaredWidth = Number(form.get("width"));
    const declaredHeight = Number(form.get("height"));
    if (!Number.isInteger(declaredWidth) || !Number.isInteger(declaredHeight)
      || declaredWidth !== dimensions.width || declaredHeight !== dimensions.height) {
      throw new HttpError(400, "invalid_image", "画像サイズを確認してください。");
    }
    const alt = requireText(form.get("alt"), "画像の説明", 1, 300);
    const mediaId = randomId();
    const originalName = (file.name || "image.webp").replace(/[\u0000-\u001F\u007F]/gu, "").slice(0, 255) || "image.webp";
    const results = await ctx.env.CMS_DB.batch([
      ctx.env.CMS_DB.prepare(
        `INSERT INTO cms_media
           (id, owner_user_id, original_name, mime_type, byte_size, width, height, sha256, data)
         SELECT ?, ?, ?, 'image/webp', ?, ?, ?, ?, ?
         WHERE COALESCE((SELECT SUM(byte_size) FROM cms_media), 0) + ? <= 300000000
           AND COALESCE((SELECT SUM(byte_size) FROM cms_media WHERE owner_user_id = ?), 0) + ? <= 100000000`,
      ).bind(
        mediaId, actor.user.id, originalName, bytes.byteLength, dimensions.width, dimensions.height,
        await sha256(bytes), bytes, bytes.byteLength, actor.user.id, bytes.byteLength,
      ),
      auditIfMediaStatement(ctx.env, requestId, actor, "media.upload", mediaId),
    ]);
    if (!results[0]?.meta.changes) {
      throw new HttpError(507, "media_quota_exceeded", "画像保存容量の上限に達しました。不要な画像を整理してください。");
    }
    return json({ id: mediaId, url: `/api/media/${mediaId}`, width: dimensions.width, height: dimensions.height, alt }, {
      status: 201,
      headers: adminHeaders(),
    });
  }
  if (!id) methodNotAllowed(["GET", "HEAD", "POST"]);
  if (!UUID_PATTERN.test(id)) throw new HttpError(404, "not_found", "画像が見つかりません。");
  if (ctx.request.method !== "DELETE") methodNotAllowed(["DELETE"]);
  const row = await ctx.env.CMS_DB.prepare(
    `SELECT id, owner_user_id,
       EXISTS(
         SELECT 1 FROM cms_articles a LEFT JOIN cms_article_media am ON am.article_id = a.id
         WHERE a.cover_media_id = cms_media.id OR am.media_id = cms_media.id
       ) AS referenced
     FROM cms_media WHERE id = ? AND deleted_at IS NULL
       ${actor.user.role === "reporter" ? "AND owner_user_id = ?" : ""}`,
  ).bind(...(actor.user.role === "reporter" ? [id, actor.user.id] : [id])).first<Record<string, unknown>>();
  if (!row) throw new HttpError(404, "not_found", "画像が見つかりません。");
  if (Number(row.referenced)) throw new HttpError(409, "media_referenced", "使用中の画像は削除できません。");
  const ownerCondition = actor.user.role === "reporter" ? " AND owner_user_id = ?" : "";
  const results = await ctx.env.CMS_DB.batch([
    auditIfMediaStatement(ctx.env, requestId, actor, "media.delete", id, true),
    ctx.env.CMS_DB.prepare(
      `DELETE FROM cms_media
       WHERE id = ? AND deleted_at IS NULL${ownerCondition}
         AND NOT EXISTS (SELECT 1 FROM cms_articles a WHERE a.cover_media_id = cms_media.id)
         AND NOT EXISTS (SELECT 1 FROM cms_article_media am WHERE am.media_id = cms_media.id)`,
    ).bind(id, ...(actor.user.role === "reporter" ? [actor.user.id] : [])),
  ]);
  if (!results[1]?.meta.changes) throw new HttpError(409, "media_referenced", "使用中の画像は削除できません。");
  return json({ deleted: true }, { headers: adminHeaders() });
}

function canMutateUser(actor: Actor, target: Record<string, unknown> | null, requestedRole: unknown): void {
  if (actor.user.role === "owner") {
    if (requestedRole === "owner" && target?.role !== "owner") throw new HttpError(403, "forbidden", "固定Ownerは追加できません。");
    return;
  }
  if (actor.user.role !== "master") throw new HttpError(403, "forbidden", "この操作を行う権限がありません。");
  const currentRole = String(target?.role ?? "");
  const nextRole = String(requestedRole ?? currentRole);
  if (currentRole === "owner" || nextRole === "owner" || (currentRole !== "master" && nextRole === "master")
    || (currentRole === "master" && nextRole !== "master")) {
    throw new HttpError(403, "forbidden", "この役割は変更できません。");
  }
}

async function users(ctx: Ctx, path: string[], requestId: string): Promise<Response> {
  const write = ctx.request.method !== "GET" && ctx.request.method !== "HEAD";
  if (write) originGuard(ctx.request);
  const actor = await actorFor(ctx.request, ctx.env, write);
  roleAtLeast(actor, ["owner", "master"]);
  const id = path[2];
  if (!id && (ctx.request.method === "GET" || ctx.request.method === "HEAD")) {
    const rows = (await ctx.env.CMS_DB.prepare(
      `SELECT id, login_id, real_name, job_title, role, status, is_fixed_owner,
        markdown_auto_convert, created_at, updated_at, version FROM cms_users ORDER BY created_at`,
    ).all<Record<string, unknown>>()).results;
    if (ctx.request.method === "HEAD") return new Response(null, { headers: adminHeaders() });
    return json({
      users: rows.map((row) => ({
        id: row.id, loginId: row.login_id, realName: row.real_name, jobTitle: row.job_title,
        role: row.role, status: row.status, isFixedOwner: Boolean(row.is_fixed_owner),
        markdownAutoConvert: Boolean(row.markdown_auto_convert), version: row.version,
      })),
    }, { headers: adminHeaders() });
  }
  if (!id && ctx.request.method === "POST") {
    const input = await body<Record<string, unknown>>(ctx.request);
    assertKeys(input, new Set(["loginId", "realName", "jobTitle", "role"]));
    const role = String(input.role);
    if (!["master", "operator", "reporter"].includes(role)) throw new HttpError(400, "invalid_request", "役割を確認してください。");
    canMutateUser(actor, null, role);
    const userId = randomId();
    const activationToken = secret();
    const timestamp = now();
    try {
      await ctx.env.CMS_DB.batch([
        ctx.env.CMS_DB.prepare(
          `INSERT INTO cms_users (id, login_id, real_name, job_title, role, status, created_by)
           VALUES (?, ?, ?, ?, ?, 'pending', ?)`,
        ).bind(
          userId, normalizeLogin(input.loginId), requireText(input.realName, "氏名", 1, 100),
          requireText(input.jobTitle, "役職", 1, 100), role, actor.user.id,
        ),
        ctx.env.CMS_DB.prepare(
          `INSERT INTO cms_user_tokens (token_hash, user_id, purpose, created_by, created_at, expires_at)
           VALUES (?, ?, 'activate', ?, ?, ?)`,
        ).bind(await sha256(activationToken), userId, actor.user.id, timestamp, new Date(Date.now() + 72 * 60 * 60_000).toISOString()),
        auditStatement(ctx.env, requestId, actor, "user.create", "user", userId),
      ]);
    } catch {
      throw new HttpError(409, "user_conflict", "同じIDのアカウントが存在します。");
    }
    return json({
      id: userId,
      activationUrl: `${new URL(ctx.request.url).origin}/admin/activate.html#token=${encodeURIComponent(activationToken)}`,
    }, { status: 201, headers: adminHeaders() });
  }
  if (!id) methodNotAllowed(["GET", "HEAD", "POST"]);
  if (!UUID_PATTERN.test(id)) throw new HttpError(404, "not_found", "対象が見つかりません。");
  const target = await ctx.env.CMS_DB.prepare("SELECT * FROM cms_users WHERE id = ?").bind(id).first<Record<string, unknown>>();
  if (!target) throw new HttpError(404, "not_found", "対象が見つかりません。");

  if (path[3] === "reset-password") {
    if (ctx.request.method !== "POST") methodNotAllowed(["POST"]);
    if (target.is_fixed_owner || target.role === "owner") throw new HttpError(403, "forbidden", "固定Ownerのパスワードはここから再設定できません。");
    // The project owner explicitly accepts normal Master -> normal Master reset.
    if (actor.user.role === "master" && !["master", "operator", "reporter"].includes(String(target.role))) {
      throw new HttpError(403, "forbidden", "この操作を行う権限がありません。");
    }
    await consumeRate(
      ctx.env,
      [await privateScopeHash(ctx.env, "password-reset-target", id)],
      10,
      24 * 60 * 60_000,
      24 * 60 * 60_000,
    );
    const resetToken = secret();
    const timestamp = now();
    const tokenPurpose = target.status === "pending" ? "activate" : "reset_password";
    const tokenLifetime = tokenPurpose === "activate" ? 72 * 60 * 60_000 : 24 * 60 * 60_000;
    await ctx.env.CMS_DB.batch([
      ctx.env.CMS_DB.prepare("DELETE FROM cms_sessions WHERE user_id = ?").bind(id),
      ctx.env.CMS_DB.prepare("DELETE FROM cms_user_tokens WHERE user_id = ? AND used_at IS NULL").bind(id),
      ctx.env.CMS_DB.prepare(
        `INSERT INTO cms_user_tokens (token_hash, user_id, purpose, created_by, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
      ).bind(await sha256(resetToken), id, tokenPurpose, actor.user.id, timestamp, new Date(Date.now() + tokenLifetime).toISOString()),
      auditStatement(ctx.env, requestId, actor, tokenPurpose === "activate" ? "user.reissue_activation" : "user.reset_password", "user", id),
    ]);
    return json({
      resetUrl: `${new URL(ctx.request.url).origin}/admin/activate.html#token=${encodeURIComponent(resetToken)}`,
    }, { headers: adminHeaders() });
  }
  if (path[3]) methodNotAllowed(["POST"]);
  if (ctx.request.method !== "PATCH") methodNotAllowed(["PATCH"]);
  const input = await body<Record<string, unknown>>(ctx.request);
  assertKeys(input, new Set(["realName", "jobTitle", "role", "status", "markdownAutoConvert", "version"]));
  if (typeof input.version !== "number" || !Number.isInteger(input.version) || input.version < 1) {
    throw new HttpError(400, "invalid_request", "更新前のバージョンを確認してください。");
  }
  const requestedVersion = input.version;
  if (requestedVersion !== Number(target.version)) {
    throw new HttpError(409, "stale_write", "他の変更があります。再読み込みしてください。");
  }
  const realName = input.realName === undefined ? String(target.real_name) : requireText(input.realName, "氏名", 1, 100);
  const jobTitle = input.jobTitle === undefined ? String(target.job_title) : requireText(input.jobTitle, "役職", 1, 100);
  const status = input.status === undefined ? String(target.status) : String(input.status);
  const role = input.role === undefined ? String(target.role) : String(input.role);
  if (input.markdownAutoConvert !== undefined && typeof input.markdownAutoConvert !== "boolean") {
    throw new HttpError(400, "invalid_request", "Markdown自動変換の設定を確認してください。");
  }
  const markdown = input.markdownAutoConvert === undefined
    ? Number(target.markdown_auto_convert)
    : input.markdownAutoConvert ? 1 : 0;
  if (!["active", "pending", "disabled"].includes(status) || !["owner", "master", "operator", "reporter"].includes(role)) {
    throw new HttpError(400, "invalid_request", "入力内容を確認してください。");
  }
  if (target.status === "pending" && status === "active") {
    throw new HttpError(400, "activation_required", "有効化リンクでパスワードを設定してください。");
  }
  canMutateUser(actor, target, role);
  if (actor.user.role === "master" && target.role === "master" && status !== target.status) {
    throw new HttpError(403, "forbidden", "他のMasterの状態は変更できません。");
  }
  if (target.is_fixed_owner && (status !== "active" || role !== "owner")) {
    throw new HttpError(403, "forbidden", "固定Ownerの権限・状態は変更できません。");
  }
  const timestamp = now();
  const nextVersion = requestedVersion + 1;
  const sensitiveChange = status !== target.status || role !== target.role;
  const masterGuard = actor.user.role !== "master"
    ? ""
    : target.role === "master" ? " AND role = 'master' AND status = ?" : " AND role NOT IN ('owner', 'master')";
  const masterGuardBindings = actor.user.role === "master" && target.role === "master" ? [target.status] : [];
  const statements: D1PreparedStatement[] = [
    ctx.env.CMS_DB.prepare(
      `UPDATE cms_users SET real_name = ?, job_title = ?, status = ?, role = ?,
       markdown_auto_convert = ?, updated_at = ?, mutation_id = ?, version = version + 1
       WHERE id = ? AND version = ?${masterGuard}`,
    ).bind(realName, jobTitle, status, role, markdown, timestamp, requestId, id, requestedVersion, ...masterGuardBindings),
  ];
  if (sensitiveChange) {
    statements.push(
      ctx.env.CMS_DB.prepare(
        `DELETE FROM cms_sessions WHERE user_id = ?
         AND EXISTS (SELECT 1 FROM cms_users WHERE id = ? AND version = ? AND mutation_id = ?)`,
      ).bind(id, id, nextVersion, requestId),
      ctx.env.CMS_DB.prepare(
        `UPDATE cms_user_tokens SET used_at = ? WHERE user_id = ? AND used_at IS NULL
         AND EXISTS (SELECT 1 FROM cms_users WHERE id = ? AND version = ? AND mutation_id = ?)`,
      ).bind(timestamp, id, id, nextVersion, requestId),
    );
  }
  statements.push(auditIfUserMutationStatement(
    ctx.env, requestId, actor, "user.update", id, requestId,
    {
      before: { role: target.role, status: target.status, version: requestedVersion },
      after: { role, status, version: nextVersion },
    },
  ));
  const results = await ctx.env.CMS_DB.batch(statements);
  if (!results[0]?.meta.changes) {
    throw new HttpError(409, "stale_write", "他の変更があります。再読み込みしてください。");
  }
  return json({ updated: true, version: nextVersion }, { headers: adminHeaders() });
}

async function auditLog(ctx: Ctx): Promise<Response> {
  if (ctx.request.method !== "GET" && ctx.request.method !== "HEAD") methodNotAllowed(["GET", "HEAD"]);
  const actor = await actorFor(ctx.request, ctx.env);
  roleAtLeast(actor, ["owner", "master"]);
  const rows = (await ctx.env.CMS_DB.prepare(
    `SELECT id, request_id, actor_user_id, actor_role, action, target_type, target_id,
      outcome, details_json, created_at FROM cms_audit_logs ORDER BY created_at DESC LIMIT 200`,
  ).all()).results;
  if (ctx.request.method === "HEAD") return new Response(null, { headers: adminHeaders() });
  return json({ logs: rows }, { headers: adminHeaders() });
}

async function auth(ctx: Ctx, path: string[], requestId: string): Promise<Response> {
  const operation = path[2];
  if (operation === "challenge") {
    if (ctx.request.method !== "POST") methodNotAllowed(["POST"]);
    return challenge(ctx);
  }
  if (operation === "login") {
    if (ctx.request.method !== "POST") methodNotAllowed(["POST"]);
    return login(ctx, requestId);
  }
  if (operation === "activate") {
    if (ctx.request.method !== "POST") methodNotAllowed(["POST"]);
    return activation(ctx, requestId);
  }
  if (operation === "change-password") {
    if (ctx.request.method !== "POST") methodNotAllowed(["POST"]);
    return changePassword(ctx, requestId);
  }
  if (operation === "me") {
    if (ctx.request.method !== "GET" && ctx.request.method !== "HEAD") methodNotAllowed(["GET", "HEAD"]);
    const actor = await actorFor(ctx.request, ctx.env);
    if (ctx.request.method === "HEAD") return new Response(null, { headers: adminHeaders() });
    return json({ user: publicUser(actor.user) }, { headers: adminHeaders() });
  }
  if (operation === "logout") {
    if (ctx.request.method !== "POST") methodNotAllowed(["POST"]);
    originGuard(ctx.request);
    const actor = await actorFor(ctx.request, ctx.env, true);
    await ctx.env.CMS_DB.batch([
      auditIfSessionStatement(ctx.env, requestId, actor, "auth.logout", "session", actor.user.id, actor.session.token_hash),
      ctx.env.CMS_DB.prepare("DELETE FROM cms_sessions WHERE token_hash = ?").bind(actor.session.token_hash),
    ]);
    return json({ loggedOut: true }, { headers: clearedAuthenticationHeaders() });
  }
  throw new HttpError(404, "not_found", "対象が見つかりません。");
}

export const onRequest: PagesFunction<Env> = async (ctx) => {
  const requestId = randomId();
  try {
    const raw = ctx.params.path;
    const path = Array.isArray(raw)
      ? raw.map(String)
      : typeof raw === "string" ? raw.split("/").filter(Boolean) : [];
    if (path[0] === "public" && path[1] === "articles") return await publicArticles(ctx, path[2]);
    if (path[0] === "media" && path[1] && path.length === 2) return await publicMedia(ctx, path[1]);
    if (path[0] === "admin" && path[1] === "setup" && path[2] === "status" && path.length === 3) {
      return await setupStatus(ctx);
    }
    if (path[0] === "admin" && path[1] === "setup" && path.length === 2) return await setup(ctx, requestId);
    if (path[0] === "admin" && path[1] === "auth") return await auth(ctx, path, requestId);
    if (path[0] === "admin" && path[1] === "articles") return await adminArticles(ctx, path, requestId);
    if (path[0] === "admin" && path[1] === "media") return await adminMedia(ctx, path[2], requestId);
    if (path[0] === "admin" && path[1] === "users") return await users(ctx, path, requestId);
    if (path[0] === "admin" && path[1] === "audit") return await auditLog(ctx);
    throw new HttpError(404, "not_found", "対象が見つかりません。");
  } catch (error) {
    return failure(error, requestId);
  }
};
