import { marked } from "marked";
import sanitizeHtml from "sanitize-html";

export type Env = CloudflareBindings & {
  CMS_BOOTSTRAP_TOKEN?: string;
  CMS_PASSWORD_PEPPER?: string;
  CMS_PASSWORD_PEPPER_PREVIOUS?: string;
  CMS_AUTH_CHALLENGE_KEY?: string;
};

export type Role = "owner" | "master" | "operator" | "reporter";
export type UserStatus = "pending" | "active" | "disabled";
export type User = {
  id: string;
  login_id: string;
  real_name: string;
  job_title: string;
  role: Role;
  status: UserStatus;
  is_fixed_owner: number;
  password_hash: string | null;
  password_salt: string | null;
  password_algorithm: string | null;
  password_iterations: number | null;
  force_password_change: number;
  markdown_auto_convert: number;
  version: number;
};
export type Session = {
  token_hash: string;
  csrf_token_hash: string;
  user_id: string;
  idle_expires_at: string;
  absolute_expires_at: string;
};
export type Actor = { user: User; session: Session; csrf: string };

export class HttpError extends Error {
  constructor(public status: number, public code: string, message: string) {
    super(message);
  }
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const COOKIE = "__Host-cms_session";
const CSRF_COOKIE = "__Host-cms_csrf";
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
const LOGIN_PATTERN = /^[a-z0-9][a-z0-9._-]{3,63}$/;
const SLUG_PATTERN = /^[a-z0-9](?:[a-z0-9-]{1,118}[a-z0-9])?$/;
const BRAND_COLOURS = new Set(["orange", "green", "blue", "navy"]);
const BODY_TAGS = [
  "p", "br", "strong", "em", "s", "del", "h2", "h3", "h4", "ul", "ol", "li",
  "blockquote", "a", "img", "code", "pre", "hr", "span",
];

export const PASSWORD_ALGORITHM = "client-pbkdf2-sha256+hmac-sha256-v1";
export const PASSWORD_ITERATIONS = 600_000;
export const SANITIZER_VERSION = "cms-allowlist-v2-sanitize-html-2";
export const BODY_SOURCE_MAX = 10_000;
export const BODY_HTML_MAX = 25_000;
export const SESSION_IDLE_MS = 30 * 60_000;
export const SESSION_ABSOLUTE_MS = 8 * 60 * 60_000;

export const now = () => new Date().toISOString();
export const randomId = () => crypto.randomUUID();

export function json(data: unknown, init: ResponseInit = {}): Response {
  const headers = new Headers(init.headers);
  headers.set("content-type", "application/json; charset=UTF-8");
  if (!headers.has("cache-control")) headers.set("cache-control", "no-store");
  headers.set("x-content-type-options", "nosniff");
  return new Response(JSON.stringify({ data }), { ...init, headers });
}

export function failure(error: unknown, requestId: string): Response {
  const safe = error instanceof HttpError
    ? error
    : new HttpError(500, "internal_error", "サーバーで問題が発生しました。");
  return new Response(JSON.stringify({ error: { code: safe.code, message: safe.message }, requestId }), {
    status: safe.status,
    headers: adminHeaders({ "content-type": "application/json; charset=UTF-8" }),
  });
}

export function adminHeaders(headers: HeadersInit = {}): Headers {
  const result = new Headers(headers);
  result.set("cache-control", "no-store");
  result.set("x-content-type-options", "nosniff");
  result.set("referrer-policy", "no-referrer");
  result.set("x-frame-options", "DENY");
  result.set("permissions-policy", "camera=(), microphone=(), geolocation=()");
  return result;
}

export async function sha256(value: string | ArrayBuffer | Uint8Array): Promise<string> {
  const bytes = typeof value === "string" ? encoder.encode(value) : value;
  const digest = await crypto.subtle.digest("SHA-256", bytes as BufferSource);
  return toBase64Url(new Uint8Array(digest));
}

export function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

export function fromBase64Url(input: string): Uint8Array {
  if (!input || !BASE64URL_PATTERN.test(input)) throw new HttpError(400, "invalid_credential", "認証情報を確認してください。");
  const padding = "=".repeat((4 - (input.length % 4)) % 4);
  try {
    return Uint8Array.from(atob(input.replaceAll("-", "+").replaceAll("_", "/") + padding), (char) => char.charCodeAt(0));
  } catch {
    throw new HttpError(400, "invalid_credential", "認証情報を確認してください。");
  }
}

export function secret(): string {
  return toBase64Url(crypto.getRandomValues(new Uint8Array(32)));
}

export function constantTimeEqual(a: string, b: string): boolean {
  const left = encoder.encode(a);
  const right = encoder.encode(b);
  const size = Math.max(left.length, right.length);
  let mismatch = left.length ^ right.length;
  for (let index = 0; index < size; index += 1) mismatch |= (left[index] ?? 0) ^ (right[index] ?? 0);
  return mismatch === 0;
}

function requiredSecret(value: string | undefined, name: string): string {
  if (!value || value.length < 32) throw new HttpError(503, "configuration_error", `${name} が設定されていません。`);
  return value;
}

async function hmac(keyValue: string, bytes: Uint8Array): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(keyValue),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return toBase64Url(new Uint8Array(await crypto.subtle.sign("HMAC", key, bytes as BufferSource)));
}

export function validateClientCredential(
  verifier: unknown,
  salt: unknown,
  iterations: unknown,
): { verifier: string; salt: string; iterations: number } {
  if (typeof verifier !== "string" || verifier.length !== 43 || fromBase64Url(verifier).byteLength !== 32) {
    throw new HttpError(400, "invalid_credential", "認証情報を確認してください。");
  }
  if (typeof salt !== "string") throw new HttpError(400, "invalid_credential", "認証情報を確認してください。");
  const saltBytes = fromBase64Url(salt);
  if (salt.length !== 43 || saltBytes.byteLength !== 32) {
    throw new HttpError(400, "invalid_credential", "認証情報を確認してください。");
  }
  if (iterations !== PASSWORD_ITERATIONS) throw new HttpError(400, "invalid_credential", "認証情報を確認してください。");
  return { verifier, salt, iterations: PASSWORD_ITERATIONS };
}

export function validateLoginVerifier(verifier: unknown): string {
  if (typeof verifier !== "string" || verifier.length !== 43 || fromBase64Url(verifier).byteLength !== 32) {
    throw new HttpError(400, "invalid_credential", "IDまたはパスワードが正しくありません。");
  }
  return verifier;
}

export async function protectVerifier(env: Env, verifier: string, previous = false): Promise<string> {
  const pepper = previous ? env.CMS_PASSWORD_PEPPER_PREVIOUS : env.CMS_PASSWORD_PEPPER;
  return hmac(requiredSecret(pepper, previous ? "CMS_PASSWORD_PEPPER_PREVIOUS" : "CMS_PASSWORD_PEPPER"), fromBase64Url(verifier));
}

export async function verifyProtectedVerifier(
  env: Env,
  verifier: string,
  storedHash: string | null,
): Promise<{ ok: boolean; usedPrevious: boolean }> {
  const current = await protectVerifier(env, verifier);
  if (storedHash && constantTimeEqual(current, storedHash)) return { ok: true, usedPrevious: false };
  if (env.CMS_PASSWORD_PEPPER_PREVIOUS) {
    const previous = await protectVerifier(env, verifier, true);
    if (storedHash && constantTimeEqual(previous, storedHash)) return { ok: true, usedPrevious: true };
  }
  return { ok: false, usedPrevious: false };
}

export async function fakePasswordSalt(env: Env, loginId: string): Promise<string> {
  const key = requiredSecret(env.CMS_AUTH_CHALLENGE_KEY, "CMS_AUTH_CHALLENGE_KEY");
  return hmac(key, encoder.encode(`fake-salt-v1\0${loginId}`));
}

export async function privateScopeHash(env: Env, label: string, value: string): Promise<string> {
  const key = requiredSecret(env.CMS_AUTH_CHALLENGE_KEY, "CMS_AUTH_CHALLENGE_KEY");
  return hmac(key, encoder.encode(`rate-limit-v1\0${label}\0${value}`));
}

export function publicUser(user: User) {
  return {
    id: user.id,
    loginId: user.login_id,
    realName: user.real_name,
    jobTitle: user.job_title,
    role: user.role,
    status: user.status,
    markdownAutoConvert: Boolean(user.markdown_auto_convert),
    forcePasswordChange: Boolean(user.force_password_change),
    version: user.version,
    isFixedOwner: Boolean(user.is_fixed_owner),
  };
}

export async function limitedRequestBytes(request: Request, maximum = 80_000): Promise<Uint8Array> {
  const declared = Number(request.headers.get("content-length") ?? 0);
  if (Number.isFinite(declared) && declared > maximum) {
    throw new HttpError(413, "request_too_large", "送信内容が大きすぎます。");
  }
  if (!request.body) return new Uint8Array();
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maximum) {
      await reader.cancel();
      throw new HttpError(413, "request_too_large", "送信内容が大きすぎます。");
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

export async function body<T>(request: Request): Promise<T> {
  const bytes = await limitedRequestBytes(request);
  try {
    return JSON.parse(decoder.decode(bytes)) as T;
  } catch {
    throw new HttpError(400, "invalid_request", "入力内容を確認してください。");
  }
}

export function requireText(value: unknown, label: string, min: number, max: number): string {
  if (typeof value !== "string") throw new HttpError(400, "invalid_request", `${label}を確認してください。`);
  const normalized = value.trim();
  if ([...normalized].length < min || [...normalized].length > max) {
    throw new HttpError(400, "invalid_request", `${label}を確認してください。`);
  }
  return normalized;
}

export function normalizeLogin(value: unknown): string {
  const login = requireText(value, "ID", 4, 64).toLowerCase();
  if (!LOGIN_PATTERN.test(login)) {
    throw new HttpError(400, "invalid_login_id", "IDは半角英小文字・数字・ピリオド・ハイフン・アンダースコアで設定してください。");
  }
  return login;
}

export function validateSlug(value: unknown): string {
  const slug = requireText(value, "URL用の名前", 3, 120).toLowerCase();
  if (!SLUG_PATTERN.test(slug)) throw new HttpError(400, "invalid_slug", "URL用の名前を確認してください。");
  return slug;
}

export function originGuard(request: Request, multipart = false): void {
  const contentType = (request.headers.get("content-type") ?? "").toLowerCase();
  if ((!multipart && !contentType.startsWith("application/json")) || (multipart && !contentType.startsWith("multipart/form-data"))) {
    throw new HttpError(415, "unsupported_media_type", "送信形式を確認してください。");
  }
  const origin = request.headers.get("origin");
  const fetchSite = request.headers.get("sec-fetch-site");
  if (!origin || origin !== new URL(request.url).origin || fetchSite === "cross-site") {
    throw new HttpError(403, "csrf_rejected", "この操作は実行できません。");
  }
}

export function cookie(request: Request, name: string): string | null {
  return request.headers.get("cookie")
    ?.split(";")
    .map((part) => part.trim())
    .find((part) => part.startsWith(`${name}=`))
    ?.slice(name.length + 1) ?? null;
}

export const sessionCookie = (token: string) => `${COOKIE}=${token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=28800`;
export const expiredCookie = () => `${COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0`;
export const csrfCookie = (token: string) => `${CSRF_COOKIE}=${token}; Path=/; Secure; SameSite=Strict; Max-Age=28800`;
export const expiredCsrfCookie = () => `${CSRF_COOKIE}=; Path=/; Secure; SameSite=Strict; Max-Age=0`;

const USER_COLUMNS = `
  u.id AS user_id, u.login_id, u.real_name, u.job_title, u.role, u.status,
  u.is_fixed_owner, u.password_hash, u.password_salt, u.password_algorithm,
  u.password_iterations, u.force_password_change, u.markdown_auto_convert, u.version AS user_version
`;

export async function actorFor(request: Request, env: Env, csrfRequired = false): Promise<Actor> {
  const rawToken = cookie(request, COOKIE);
  if (!rawToken) throw new HttpError(401, "authentication_required", "ログインが必要です。");
  const tokenHash = await sha256(rawToken);
  const timestamp = now();
  const row = await env.CMS_DB.prepare(
    `SELECT
       s.token_hash, s.csrf_token_hash, s.user_id AS session_user_id,
       s.idle_expires_at, s.absolute_expires_at,
       ${USER_COLUMNS}
     FROM cms_sessions s
     JOIN cms_users u ON u.id = s.user_id
     WHERE s.token_hash = ?
       AND s.idle_expires_at > ?
       AND s.absolute_expires_at > ?
       AND u.status = 'active'`,
  ).bind(tokenHash, timestamp, timestamp).first<Record<string, unknown>>();
  if (!row) throw new HttpError(401, "authentication_required", "ログインが必要です。");

  const user: User = {
    id: String(row.user_id), login_id: String(row.login_id), real_name: String(row.real_name),
    job_title: String(row.job_title), role: row.role as Role, status: row.status as UserStatus,
    is_fixed_owner: Number(row.is_fixed_owner), password_hash: row.password_hash as string | null,
    password_salt: row.password_salt as string | null, password_algorithm: row.password_algorithm as string | null,
    password_iterations: row.password_iterations as number | null,
    force_password_change: Number(row.force_password_change), markdown_auto_convert: Number(row.markdown_auto_convert),
    version: Number(row.user_version),
  };
  const session: Session = {
    token_hash: String(row.token_hash), csrf_token_hash: String(row.csrf_token_hash),
    user_id: String(row.session_user_id), idle_expires_at: String(row.idle_expires_at),
    absolute_expires_at: String(row.absolute_expires_at),
  };

  const csrf = request.headers.get("x-csrf-token") ?? "";
  if (csrfRequired && !constantTimeEqual(await sha256(csrf), session.csrf_token_hash)) {
    throw new HttpError(403, "csrf_rejected", "この操作は実行できません。");
  }
  const idleLimit = Math.min(Date.now() + SESSION_IDLE_MS, Date.parse(session.absolute_expires_at));
  await env.CMS_DB.prepare("UPDATE cms_sessions SET last_seen_at = ?, idle_expires_at = ? WHERE token_hash = ?")
    .bind(timestamp, new Date(idleLimit).toISOString(), tokenHash).run();
  return { user, session, csrf };
}

export function roleAtLeast(actor: Actor, roles: Role[]): void {
  if (!roles.includes(actor.user.role)) throw new HttpError(403, "forbidden", "この操作を行う権限がありません。");
}

export async function audit(
  env: Env,
  requestId: string,
  actor: Actor | null,
  action: string,
  targetType: string,
  targetId: string | null,
  outcome: "success" | "denied" | "failure" = "success",
  details: unknown = {},
): Promise<void> {
  let serialized = JSON.stringify(details);
  if (serialized.length > 20_000) serialized = JSON.stringify({ truncated: true });
  await env.CMS_DB.prepare(
    `INSERT INTO cms_audit_logs
       (id, request_id, actor_user_id, actor_role, action, target_type, target_id, outcome, details_json)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).bind(randomId(), requestId, actor?.user.id ?? null, actor?.user.role ?? null, action, targetType, targetId, outcome, serialized).run();
}

function safeBodyHref(value: string): string | null {
  if (/[\u0000-\u001F\u007F\\\\]/u.test(value) || value.startsWith("//")) return null;
  if (value.startsWith("/")) {
    if (value.startsWith("/api/media/") || value.startsWith("/news/") || value.startsWith("/activity")) return value;
    return null;
  }
  try {
    const url = new URL(value);
    if (url.protocol !== "https:" || url.username || url.password) return null;
    return url.href;
  } catch {
    return null;
  }
}

export function renderBody(source: string, format: "markdown" | "html"): string {
  if (source.length > BODY_SOURCE_MAX) throw new HttpError(400, "body_too_large", "本文が長すぎます。");
  const raw = format === "markdown" ? marked.parse(source, { async: false, gfm: true, breaks: true }) : source;
  const sanitized = sanitizeHtml(String(raw), {
    allowedTags: BODY_TAGS,
    allowedAttributes: { a: ["href", "title", "target", "rel"], img: ["src", "alt"], span: ["class"] },
    allowedSchemes: ["https"],
    allowProtocolRelative: false,
    transformTags: {
      a: (_tagName, attributes) => {
        const href = safeBodyHref(attributes.href ?? "");
        if (!href) return { tagName: "span", attribs: {} };
        const external = href.startsWith("https://");
        return {
          tagName: "a",
          attribs: {
            href,
            ...(attributes.title ? { title: attributes.title.slice(0, 300) } : {}),
            ...(external ? { target: "_blank", rel: "noopener noreferrer" } : {}),
          },
        };
      },
      img: (_tagName, attributes) => {
        const sourceValue = attributes.src ?? "";
        const mediaPattern = new RegExp(`^/api/media/${UUID_PATTERN.source.slice(1, -1)}$`, "i");
        if (!mediaPattern.test(sourceValue)) return { tagName: "span", attribs: {} };
        const alt = (attributes.alt ?? "").trim().slice(0, 300);
        if (!alt) return { tagName: "span", attribs: {} };
        return { tagName: "img", attribs: { src: sourceValue, alt } };
      },
      span: (_tagName, attributes) => {
        const requested = attributes["data-brand-color"] ?? attributes.class?.replace("text-color-", "");
        const colour = requested && BRAND_COLOURS.has(requested) ? requested : null;
        return { tagName: "span", attribs: colour ? { class: `text-color-${colour}` } : {} };
      },
    },
  });
  if (sanitized.length > BODY_HTML_MAX) throw new HttpError(400, "body_too_large", "本文が長すぎます。");
  return sanitized;
}

function safeAssetPath(value: unknown): string | null {
  if (typeof value !== "string" || value.length < 1 || value.length > 2048
    || /[\u0000-\u001F\u007F\\\\]/u.test(value) || value.startsWith("//")) return null;
  try {
    const decoded = decodeURIComponent(value);
    if (/[\u0000-\u001F\u007F\\\\]/u.test(decoded) || decoded.startsWith("//")) return null;
    const url = new URL(value, "https://cms.invalid");
    if (url.origin !== "https://cms.invalid" || !url.pathname.startsWith("/assets/")) return null;
    const decodedPath = decodeURIComponent(url.pathname);
    if (decodedPath.split("/").some((segment) => segment === "." || segment === "..")) return null;
    return value;
  } catch {
    return null;
  }
}

export function safeActionUrl(value: unknown): string {
  const input = requireText(value, "URL", 1, 2048);
  if (input.startsWith("/")) {
    const assetPath = safeAssetPath(input);
    if (!assetPath) {
      throw new HttpError(400, "invalid_url", "サイト内URLは安全な /assets/ パスだけ指定できます。");
    }
    return assetPath;
  }
  if (/[\u0000-\u001F\u007F\\\\]/u.test(input) || input.startsWith("//")) {
    throw new HttpError(400, "invalid_url", "URLを確認してください。");
  }
  try {
    const url = new URL(input);
    if (url.protocol !== "https:" || url.username || url.password) throw new Error("unsafe");
    return url.href;
  } catch {
    throw new HttpError(400, "invalid_url", "外部URLは https:// から始めてください。");
  }
}

export function safeActionUrlForRead(value: unknown): string | null {
  try { return safeActionUrl(value); } catch { return null; }
}

export function safeLegacyCoverPath(value: unknown): string {
  const path = safeAssetPath(value);
  if (!path) return "";
  const parsed = new URL(path, "https://cms.invalid");
  return parsed.search || parsed.hash ? "" : path;
}

function uint32le(bytes: Uint8Array, offset: number): number {
  return ((bytes[offset] ?? 0)
    | ((bytes[offset + 1] ?? 0) << 8)
    | ((bytes[offset + 2] ?? 0) << 16)
    | ((bytes[offset + 3] ?? 0) << 24)) >>> 0;
}

export function webpDimensions(bytes: Uint8Array): { width: number; height: number } | null {
  if (bytes.byteLength < 20 || decoder.decode(bytes.slice(0, 4)) !== "RIFF" || decoder.decode(bytes.slice(8, 12)) !== "WEBP") return null;
  if (uint32le(bytes, 4) !== bytes.byteLength - 8) return null;
  let offset = 12;
  let canvas: { width: number; height: number } | null = null;
  let payload: { width: number; height: number } | null = null;
  let payloadType: "VP8" | "VP8L" | null = null;
  let extendedFlags: number | null = null;
  let alphaChunks = 0;
  while (offset + 8 <= bytes.byteLength) {
    const type = decoder.decode(bytes.slice(offset, offset + 4));
    const chunkSize = uint32le(bytes, offset + 4);
    const dataOffset = offset + 8;
    const end = dataOffset + chunkSize;
    if (end > bytes.byteLength) return null;
    if (["EXIF", "XMP ", "ICCP", "ANIM", "ANMF"].includes(type)) return null;
    if (type === "VP8X") {
      const flags = bytes[dataOffset] ?? 0;
      if (canvas || payload || offset !== 12 || chunkSize !== 10 || (flags & 0xef) !== 0) return null;
      extendedFlags = flags;
      canvas = {
        width: 1 + (bytes[dataOffset + 4] ?? 0) + ((bytes[dataOffset + 5] ?? 0) << 8) + ((bytes[dataOffset + 6] ?? 0) << 16),
        height: 1 + (bytes[dataOffset + 7] ?? 0) + ((bytes[dataOffset + 8] ?? 0) << 8) + ((bytes[dataOffset + 9] ?? 0) << 16),
      };
    } else if (type === "ALPH") {
      alphaChunks += 1;
      if (alphaChunks !== 1 || payload || extendedFlags === null || (extendedFlags & 0x10) === 0 || chunkSize < 1) return null;
    } else if (type === "VP8 ") {
      if (payload || chunkSize < 10 || bytes[dataOffset + 3] !== 0x9d || bytes[dataOffset + 4] !== 0x01 || bytes[dataOffset + 5] !== 0x2a) return null;
      payload = {
        width: (bytes[dataOffset + 6] ?? 0) | (((bytes[dataOffset + 7] ?? 0) & 0x3f) << 8),
        height: (bytes[dataOffset + 8] ?? 0) | (((bytes[dataOffset + 9] ?? 0) & 0x3f) << 8),
      };
      payloadType = "VP8";
    } else if (type === "VP8L") {
      if (payload || alphaChunks || chunkSize < 5 || bytes[dataOffset] !== 0x2f) return null;
      const b0 = bytes[dataOffset + 1] ?? 0;
      const b1 = bytes[dataOffset + 2] ?? 0;
      const b2 = bytes[dataOffset + 3] ?? 0;
      const b3 = bytes[dataOffset + 4] ?? 0;
      if ((b3 & 0xe0) !== 0) return null;
      payload = {
        width: 1 + (((b1 & 0x3f) << 8) | b0),
        height: 1 + (((b3 & 0x0f) << 10) | (b2 << 2) | ((b1 & 0xc0) >> 6)),
      };
      payloadType = "VP8L";
    }
    const next = end + (chunkSize % 2);
    if (next > bytes.byteLength) return null;
    offset = next;
  }
  if (offset !== bytes.byteLength || !payload) return null;
  if (canvas && (canvas.width !== payload.width || canvas.height !== payload.height)) return null;
  if (extendedFlags !== null && payloadType === "VP8" && Boolean(extendedFlags & 0x10) !== Boolean(alphaChunks)) return null;
  const dimensions = canvas ?? payload;
  if (dimensions.width < 1 || dimensions.height < 1 || dimensions.width > 1920 || dimensions.height > 1920) return null;
  if (payload.width < 1 || payload.height < 1 || payload.width > 1920 || payload.height > 1920) return null;
  if (dimensions.width * dimensions.height > 3_686_400 || payload.width * payload.height > 3_686_400) return null;
  return dimensions;
}

export const esc = (value: string) => value
  .replaceAll("&", "&amp;")
  .replaceAll("<", "&lt;")
  .replaceAll(">", "&gt;")
  .replaceAll('"', "&quot;")
  .replaceAll("'", "&#39;");
