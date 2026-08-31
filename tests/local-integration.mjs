import assert from "node:assert/strict";

const base = process.env.CMS_TEST_BASE_URL || "http://127.0.0.1:8788";
const bootstrapToken = "local-integration-bootstrap-token-not-for-production-2026";
const iterations = 600_000;
const ownerCredentials = { loginId: "owner-local", password: "LocalIntegrationOwner!2026" };

const encoder = new TextEncoder();
const checks = [];
const runIp = `2001:db8:${crypto.randomUUID().replaceAll("-", "").slice(0, 4)}:${crypto.randomUUID().replaceAll("-", "").slice(0, 4)}::1`;

function base64Url(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

function decodeBase64Url(value) {
  return new Uint8Array(Buffer.from(value, "base64url"));
}

async function deriveVerifier(password, salt, rounds = iterations) {
  const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: rounds },
    key,
    256,
  );
  return base64Url(new Uint8Array(bits));
}

async function call(path, { method = "GET", payload, cookie, csrf, expected = 200, ip = runIp } = {}) {
  const headers = new Headers({ Accept: "application/json", "cf-connecting-ip": ip });
  if (payload !== undefined) {
    headers.set("content-type", "application/json");
    headers.set("origin", base);
    headers.set("sec-fetch-site", "same-origin");
  }
  if (cookie) headers.set("cookie", cookie);
  if (csrf) headers.set("x-csrf-token", csrf);
  const response = await fetch(`${base}${path}`, {
    method,
    headers,
    body: payload === undefined ? undefined : JSON.stringify(payload),
    redirect: "manual",
  });
  const raw = await response.text();
  let parsed = {};
  if (raw) {
    try { parsed = JSON.parse(raw); } catch { parsed = { raw }; }
  }
  const expectedStatuses = Array.isArray(expected) ? expected : [expected];
  assert.ok(expectedStatuses.includes(response.status), `${method} ${path}: expected ${expectedStatuses.join("/")}, got ${response.status}: ${raw.slice(0, 300)}`);
  return { response, status: response.status, data: parsed.data, error: parsed.error, raw };
}

function syntheticWebp(width = 2, height = 2) {
  return new Uint8Array([
    0x52, 0x49, 0x46, 0x46, 22, 0, 0, 0, 0x57, 0x45, 0x42, 0x50,
    0x56, 0x50, 0x38, 0x20, 10, 0, 0, 0,
    0, 0, 0, 0x9d, 0x01, 0x2a,
    width & 0xff, (width >>> 8) & 0x3f, height & 0xff, (height >>> 8) & 0x3f,
  ]);
}

async function uploadMedia(session, suffix) {
  const form = new FormData();
  form.append("image", new Blob([syntheticWebp()], { type: "image/webp" }), `synthetic-${suffix}.webp`);
  form.append("width", "2");
  form.append("height", "2");
  form.append("alt", "ローカル結合テスト用の合成画像");
  const response = await fetch(`${base}/api/admin/media`, {
    method: "POST",
    headers: {
      Accept: "application/json",
      Origin: base,
      "Sec-Fetch-Site": "same-origin",
      "CF-Connecting-IP": runIp,
      Cookie: session.cookie,
      "X-CSRF-Token": session.csrf,
    },
    body: form,
  });
  const payload = await response.json();
  assert.equal(response.status, 201, JSON.stringify(payload));
  assert.match(payload.data.id, /^[0-9a-f-]{36}$/u);
  return payload.data;
}

async function createCredential(password) {
  const salt = crypto.getRandomValues(new Uint8Array(32));
  return {
    passwordVerifier: await deriveVerifier(password, salt),
    passwordSalt: base64Url(salt),
    passwordIterations: iterations,
  };
}

function tokenFromUrl(value) {
  const parsed = new URL(value);
  return new URLSearchParams(parsed.hash.slice(1)).get("token") || parsed.searchParams.get("token");
}

async function loginAttempt(loginId, password, expected = [200, 401, 429]) {
  const challenge = await call("/api/admin/auth/challenge", {
    method: "POST",
    payload: { loginId },
  });
  const passwordVerifier = await deriveVerifier(password, decodeBase64Url(challenge.data.salt), challenge.data.iterations);
  return call("/api/admin/auth/login", {
    method: "POST",
    payload: { loginId, passwordVerifier },
    expected,
  });
}

async function login(loginId, password) {
  const challenge = await call("/api/admin/auth/challenge", {
    method: "POST",
    payload: { loginId },
  });
  assert.equal(challenge.data.iterations, iterations);
  const passwordVerifier = await deriveVerifier(password, decodeBase64Url(challenge.data.salt), challenge.data.iterations);
  const loggedIn = await call("/api/admin/auth/login", {
    method: "POST",
    payload: { loginId, passwordVerifier },
  });
  const setCookies = typeof loggedIn.response.headers.getSetCookie === "function"
    ? loggedIn.response.headers.getSetCookie()
    : (loggedIn.response.headers.get("set-cookie") ?? "").split(/,\s*(?=__Host-)/u);
  const sessionCookie = setCookies.find((value) => value.startsWith("__Host-cms_session="));
  const csrfCookie = setCookies.find((value) => value.startsWith("__Host-cms_csrf="));
  assert.ok(sessionCookie?.includes("Secure"));
  assert.ok(sessionCookie.includes("HttpOnly"));
  assert.ok(sessionCookie.includes("SameSite=Strict"));
  assert.ok(csrfCookie?.includes("Secure"));
  assert.ok(!csrfCookie.includes("HttpOnly"));
  assert.ok(csrfCookie.includes("SameSite=Strict"));
  const cookie = [sessionCookie, csrfCookie].map((value) => value.split(";", 1)[0]).join("; ");
  const me = await call("/api/admin/auth/me", { cookie });
  assert.equal(me.data.user.loginId, loginId);
  assert.equal(me.data.csrfToken, undefined);
  assert.match(loggedIn.data.csrfToken, /^[A-Za-z0-9_-]{43}$/u);
  return { cookie, csrf: loggedIn.data.csrfToken, user: me.data.user };
}

async function activate(url, password) {
  const token = tokenFromUrl(url);
  assert.ok(token);
  await call("/api/admin/auth/activate", {
    method: "POST",
    payload: { token, ...(await createCredential(password)) },
  });
}

async function createUser(owner, profile, password) {
  const created = await call("/api/admin/users", {
    method: "POST",
    cookie: owner.cookie,
    csrf: owner.csrf,
    payload: profile,
    expected: 201,
  });
  assert.ok(created.data.activationUrl);
  await activate(created.data.activationUrl, password);
  return created.data.id;
}

async function createArticle(session, suffix, title, coverMediaId = null) {
  const created = await call("/api/admin/articles", {
    method: "POST",
    cookie: session.cookie,
    csrf: session.csrf,
    expected: 201,
    payload: {
      contentKind: "article",
      title,
      subtitle: "HTTP結合テスト用サブタイトル",
      summary: "ローカル合成データだけを使うHTTP結合テスト用の記事です。",
      category: "テスト",
      coverAlt: "テスト用アイキャッチ画像の説明",
      coverMediaId: coverMediaId || undefined,
      bodyFormat: "html",
      bodyHtml: `<h2>見出し ${suffix}</h2><p><strong>太字</strong>と<span data-brand-color="orange">ブランド色</span></p><script>alert(1)</script><img src="https://attacker.example/a.webp" alt="外部画像">`,
      bodySource: "",
      markdownAutoConvert: false,
      actions: [],
    },
  });
  assert.equal(created.data.article.status, "draft");
  assert.ok(created.data.article.bodyHtml.includes('class="text-color-orange"'));
  assert.ok(!created.data.article.bodyHtml.includes("<script"));
  assert.ok(!created.data.article.bodyHtml.includes("attacker.example"));
  return created.data.article;
}

async function transition(session, articleId, operation, expectedStatus) {
  const result = await call(`/api/admin/articles/${articleId}/${operation}`, {
    method: "POST",
    cookie: session.cookie,
    csrf: session.csrf,
    payload: {},
  });
  assert.equal(result.data.article.status, expectedStatus);
  return result.data.article;
}

async function softDelete(session, articleId) {
  const result = await call(`/api/admin/articles/${articleId}`, {
    method: "DELETE",
    cookie: session.cookie,
    csrf: session.csrf,
    payload: {},
  });
  assert.equal(result.data.article.status, "deleted");
}

async function permanentDelete(session, articleId) {
  await call(`/api/admin/articles/${articleId}/permanent`, {
    method: "DELETE",
    cookie: session.cookie,
    csrf: session.csrf,
    payload: {},
  });
}

async function main() {
  const setupStatus = await call("/api/admin/setup/status");
  await call("/api/admin/setup/status", { method: "POST", payload: {}, expected: 405 });
  await call("/api/admin/setup", { expected: 405 });
  if (setupStatus.data.required) {
    await call("/api/admin/setup", {
      method: "POST",
      expected: 201,
      payload: {
        bootstrapToken,
        loginId: ownerCredentials.loginId,
        realName: "ローカル固定Owner",
        jobTitle: "結合テスト",
        ...(await createCredential(ownerCredentials.password)),
      },
    });
  }
  checks.push("fixed Owner setup");

  const owner = await login(ownerCredentials.loginId, ownerCredentials.password);
  assert.equal(owner.user.role, "owner");
  checks.push("challenge/PBKDF2/HMAC login and session");

  const workshop = await call("/api/admin/articles/art_workshop_20260819", { cookie: owner.cookie });
  assert.equal(workshop.data.article.contentKind, "legacy_link");
  const workshopActions = workshop.data.article.actions;
  assert.ok(workshopActions.some((action) => action.url.startsWith("/assets/") && action.behavior === "download"));
  assert.ok(workshopActions.some((action) => action.url.startsWith("https://") && action.behavior === "new_tab"));
  const workshopUpdated = await call("/api/admin/articles/art_workshop_20260819", {
    method: "PATCH",
    cookie: owner.cookie,
    csrf: owner.csrf,
    payload: {
      version: workshop.data.article.version,
      contentKind: "legacy_link",
      title: workshop.data.article.title,
      subtitle: workshop.data.article.subtitle || "移行済みリンク型お知らせ",
      summary: workshop.data.article.summary,
      category: workshop.data.article.category,
      coverAlt: workshop.data.article.coverAlt,
      actions: workshopActions,
    },
  });
  assert.equal(workshopUpdated.data.article.bodyFormat, "none");
  assert.ok(workshopUpdated.data.article.actions.some((action) => action.url.startsWith("/assets/")));
  checks.push("legacy metadata update preserves relative PDF and external form actions");

  const publicSeed = await call("/api/public/articles?limit=20");
  assert.equal(publicSeed.data.articles.length >= 4, true);
  assert.equal(publicSeed.data.articles.filter((item) => item.contentKind === "legacy_link").length >= 2, true);
  assert.equal(publicSeed.data.articles.flatMap((item) => item.actions || []).length >= 3, true);
  checks.push("public seed articles and legacy actions");

  const suffix = `${Date.now().toString(36)}-${crypto.randomUUID().slice(0, 6)}`;
  const reporterLogin = `reporter-${suffix}`;
  const operatorLogin = `operator-${suffix}`;
  const masterALogin = `master-a-${suffix}`;
  const masterBLogin = `master-b-${suffix}`;
  const reporterPassword = "LocalIntegrationReporter!2026";
  const operatorPassword = "LocalIntegrationOperator!2026";
  const masterAPassword = "LocalIntegrationMasterA!2026";
  const masterBPassword = "LocalIntegrationMasterB!2026";

  await createUser(owner, { loginId: reporterLogin, realName: "ローカル記者", jobTitle: "Reporter", role: "reporter" }, reporterPassword);
  await createUser(owner, { loginId: operatorLogin, realName: "ローカル運用者", jobTitle: "Operator", role: "operator" }, operatorPassword);
  await createUser(owner, { loginId: masterALogin, realName: "ローカルMaster A", jobTitle: "Master", role: "master" }, masterAPassword);
  const masterBId = await createUser(owner, { loginId: masterBLogin, realName: "ローカルMaster B", jobTitle: "Master", role: "master" }, masterBPassword);
  checks.push("Owner account creation and activation");

  const raceLogin = `token-race-${suffix}`;
  const raceUser = await call("/api/admin/users", {
    method: "POST",
    cookie: owner.cookie,
    csrf: owner.csrf,
    expected: 201,
    payload: { loginId: raceLogin, realName: "トークン競合テスト", jobTitle: "Reporter", role: "reporter" },
  });
  const raceToken = tokenFromUrl(raceUser.data.activationUrl);
  assert.ok(raceToken);
  const [credentialA, credentialB] = await Promise.all([
    createCredential("TokenRacePasswordA!2026"),
    createCredential("TokenRacePasswordB!2026"),
  ]);
  const activationRace = await Promise.all([
    call("/api/admin/auth/activate", {
      method: "POST", payload: { token: raceToken, ...credentialA }, expected: [200, 400],
    }),
    call("/api/admin/auth/activate", {
      method: "POST", payload: { token: raceToken, ...credentialB }, expected: [200, 400],
    }),
  ]);
  assert.deepEqual(activationRace.map((result) => result.status).sort((a, b) => a - b), [200, 400]);
  const passwordRace = await Promise.all([
    loginAttempt(raceLogin, "TokenRacePasswordA!2026", [200, 401]),
    loginAttempt(raceLogin, "TokenRacePasswordB!2026", [200, 401]),
  ]);
  assert.deepEqual(passwordRace.map((result) => result.status).sort((a, b) => a - b), [200, 401]);
  const activationAudit = await call("/api/admin/audit", { cookie: owner.cookie });
  assert.equal(activationAudit.data.logs.filter((entry) => entry.target_id === raceUser.data.id && entry.action === "user.activate").length, 1);
  await call("/api/admin/auth/activate", {
    method: "POST", payload: { token: raceToken, ...credentialA }, expected: 400,
  });
  checks.push("one-time activation token has exactly one concurrent winner");

  const reporter = await login(reporterLogin, reporterPassword);
  const operator = await login(operatorLogin, operatorPassword);
  const masterA = await login(masterALogin, masterAPassword);
  const masterB = await login(masterBLogin, masterBPassword);
  assert.deepEqual([reporter.user.role, operator.user.role, masterA.user.role, masterB.user.role], ["reporter", "operator", "master", "master"]);

  const usersForOwner = await call("/api/admin/users", { cookie: owner.cookie });
  const reporterRecord = usersForOwner.data.users.find((user) => user.loginId === reporterLogin);
  assert.ok(reporterRecord);
  await call(`/api/admin/users/${reporterRecord.id}`, {
    method: "PATCH", cookie: owner.cookie, csrf: owner.csrf,
    payload: { realName: "versionなし" }, expected: 400,
  });
  const userPatchRace = await Promise.all([
    call(`/api/admin/users/${reporterRecord.id}`, {
      method: "PATCH", cookie: owner.cookie, csrf: owner.csrf,
      payload: { realName: "競合A", version: reporterRecord.version }, expected: [200, 409],
    }),
    call(`/api/admin/users/${reporterRecord.id}`, {
      method: "PATCH", cookie: owner.cookie, csrf: owner.csrf,
      payload: { realName: "競合B", version: reporterRecord.version }, expected: [200, 409],
    }),
  ]);
  assert.deepEqual(userPatchRace.map((result) => result.status).sort((a, b) => a - b), [200, 409]);
  const usersAfterRace = await call("/api/admin/users", { cookie: owner.cookie });
  const reporterAfterRace = usersAfterRace.data.users.find((user) => user.id === reporterRecord.id);
  assert.equal(reporterAfterRace.version, reporterRecord.version + 1);
  const userRaceAudit = await call("/api/admin/audit", { cookie: owner.cookie });
  assert.equal(userRaceAudit.data.logs.filter((entry) => entry.target_id === reporterRecord.id && entry.action === "user.update").length, 1);
  checks.push("user optimistic version permits one concurrent winner without side effects");

  const disposableMedia = await uploadMedia(owner, `${suffix}-delete`);
  await call(`/api/media/${disposableMedia.id}`, { expected: 401 });
  await call(`/api/admin/media/${disposableMedia.id}`, {
    method: "DELETE", cookie: owner.cookie, csrf: owner.csrf, payload: {},
  });
  await call(`/api/media/${disposableMedia.id}`, { expected: 404 });

  const coverMedia = await uploadMedia(owner, `${suffix}-cover`);
  let mediaArticle = await createArticle(owner, `${suffix}-media`, `画像参照記事 ${suffix}`, coverMedia.id);
  await call(`/api/admin/media/${coverMedia.id}`, {
    method: "DELETE", cookie: owner.cookie, csrf: owner.csrf, payload: {}, expected: 409,
  });
  mediaArticle = await transition(owner, mediaArticle.id, "publish", "published");
  const publicImage = await fetch(`${base}/api/media/${coverMedia.id}`);
  assert.equal(publicImage.status, 200);
  assert.equal(publicImage.headers.get("content-type"), "image/webp");
  assert.match(publicImage.headers.get("cache-control") ?? "", /no-store/u);
  await transition(owner, mediaArticle.id, "unpublish", "unpublished");
  await call(`/api/media/${coverMedia.id}`, { expected: 401 });
  await softDelete(owner, mediaArticle.id);
  await permanentDelete(owner, mediaArticle.id);
  await call(`/api/admin/media/${coverMedia.id}`, {
    method: "DELETE", cookie: owner.cookie, csrf: owner.csrf, payload: {},
  });
  checks.push("D1 WebP upload, private/public access, reference guard and physical delete");

  let ownerArticle = await createArticle(owner, suffix, `Owner記事 ${suffix}`);
  const articlePatch = (marker) => ({
    version: ownerArticle.version,
    contentKind: "article",
    title: `Owner記事 ${suffix} ${marker}`,
    subtitle: ownerArticle.subtitle,
    summary: ownerArticle.summary,
    category: ownerArticle.category,
    coverAlt: ownerArticle.coverAlt,
    bodyFormat: "html",
    bodyHtml: `<h2>競合${marker}</h2><p>同時更新の勝者だけを保存します。</p>`,
    markdownAutoConvert: false,
    actions: [],
  });
  const articlePatchRace = await Promise.all([
    call(`/api/admin/articles/${ownerArticle.id}`, {
      method: "PATCH", cookie: owner.cookie, csrf: owner.csrf,
      payload: articlePatch("A"), expected: [200, 409],
    }),
    call(`/api/admin/articles/${ownerArticle.id}`, {
      method: "PATCH", cookie: owner.cookie, csrf: owner.csrf,
      payload: articlePatch("B"), expected: [200, 409],
    }),
  ]);
  assert.deepEqual(articlePatchRace.map((result) => result.status).sort((a, b) => a - b), [200, 409]);
  ownerArticle = (await call(`/api/admin/articles/${ownerArticle.id}`, { cookie: owner.cookie })).data.article;
  assert.equal(ownerArticle.version, 2);
  const articleRaceAudit = await call("/api/admin/audit", { cookie: owner.cookie });
  assert.equal(articleRaceAudit.data.logs.filter((entry) => entry.target_id === ownerArticle.id && entry.action === "article.update").length, 1);
  checks.push("article optimistic mutation keeps one concurrent winner");
  const markdownSource = `## Markdown見出し ${suffix}\n\n**太字**と[安全なリンク](https://example.com/)\n\n<script>alert(1)</script>`;
  const markdownUpdate = await call(`/api/admin/articles/${ownerArticle.id}`, {
    method: "PATCH",
    cookie: owner.cookie,
    csrf: owner.csrf,
    payload: {
      version: ownerArticle.version,
      contentKind: "article",
      title: ownerArticle.title,
      subtitle: ownerArticle.subtitle,
      summary: ownerArticle.summary,
      category: ownerArticle.category,
      coverAlt: ownerArticle.coverAlt,
      bodyFormat: "markdown",
      bodySource: markdownSource,
      markdownAutoConvert: true,
      actions: [],
    },
  });
  ownerArticle = markdownUpdate.data.article;
  assert.equal(ownerArticle.bodyFormat, "markdown");
  assert.equal(ownerArticle.bodySource, markdownSource);
  assert.ok(ownerArticle.bodyHtml.includes("<h2>"));
  assert.ok(ownerArticle.bodyHtml.includes("<strong>太字</strong>"));
  assert.ok(!ownerArticle.bodyHtml.includes("<script"));
  await transition(owner, ownerArticle.id, "publish", "published");
  const detail = await call(`/api/public/articles/${ownerArticle.slug}`);
  assert.equal(detail.data.article.author.realName, "ローカル固定Owner");
  assert.equal(detail.data.related.length, 3);
  const html = await fetch(`${base}/news/${ownerArticle.slug}`).then(async (response) => ({ response, text: await response.text() }));
  assert.equal(html.response.status, 200);
  assert.ok(html.text.includes(`Owner記事 ${suffix}`));
  assert.ok(html.text.includes("ローカル固定Owner"));
  assert.ok(!html.text.includes("<script>alert(1)</script>"));
  checks.push("rich HTML sanitize, Markdown persistence, publish, public JSON and SSR");

  await call(`/api/admin/articles/${ownerArticle.id}`, { cookie: reporter.cookie, expected: 404 });
  await call("/api/admin/users", { cookie: reporter.cookie, expected: 403 });
  const reporterArticle = await createArticle(reporter, suffix, `Reporter記事 ${suffix}`);
  await transition(reporter, reporterArticle.id, "publish", "published");
  await transition(reporter, reporterArticle.id, "unpublish", "unpublished");
  await call(`/api/admin/articles/${reporterArticle.id}/permanent`, {
    method: "DELETE",
    cookie: reporter.cookie,
    csrf: reporter.csrf,
    payload: {},
    expected: 403,
  });
  checks.push("Reporter own-only CRUD/publish and permission denials");

  await call("/api/admin/users", { cookie: operator.cookie, expected: 403 });
  const operatorArticle = await createArticle(operator, suffix, `Operator記事 ${suffix}`);
  await call(`/api/admin/articles/${ownerArticle.id}`, { cookie: operator.cookie });
  await call(`/api/admin/articles/${operatorArticle.id}/permanent`, {
    method: "DELETE",
    cookie: operator.cookie,
    csrf: operator.csrf,
    payload: {},
    expected: 403,
  });
  checks.push("Operator article access and user/permanent-delete denials");

  const usersForMaster = await call("/api/admin/users", { cookie: masterA.cookie });
  const masterBRecord = usersForMaster.data.users.find((user) => user.id === masterBId);
  assert.ok(masterBRecord);
  await call("/api/admin/users", {
    method: "POST",
    cookie: masterA.cookie,
    csrf: masterA.csrf,
    payload: { loginId: `master-c-${suffix}`, realName: "禁止Master", jobTitle: "Master", role: "master" },
    expected: 403,
  });
  await call(`/api/admin/users/${masterBId}`, {
    method: "PATCH",
    cookie: masterA.cookie,
    csrf: masterA.csrf,
    payload: { status: "disabled", version: masterBRecord.version },
    expected: 403,
  });
  const reset = await call(`/api/admin/users/${masterBId}/reset-password`, {
    method: "POST",
    cookie: masterA.cookie,
    csrf: masterA.csrf,
    payload: {},
  });
  assert.ok(reset.data.resetUrl);
  await call("/api/admin/auth/me", { cookie: masterB.cookie, expected: 401 });
  checks.push("Master role boundary and accepted Master-to-Master reset");

  await transition(owner, ownerArticle.id, "unpublish", "unpublished");
  await call(`/api/public/articles/${ownerArticle.slug}`, { expected: 404 });
  await softDelete(owner, ownerArticle.id);
  await transition(owner, ownerArticle.id, "restore", "unpublished");
  await softDelete(owner, ownerArticle.id);
  await permanentDelete(masterA, ownerArticle.id);

  await softDelete(reporter, reporterArticle.id);
  await permanentDelete(owner, reporterArticle.id);
  await softDelete(operator, operatorArticle.id);
  await permanentDelete(owner, operatorArticle.id);
  checks.push("unpublish, restore, soft delete and non-recommended permanent delete");

  const passwordChallengeResult = await call("/api/admin/auth/challenge", {
    method: "POST", payload: { loginId: reporterLogin },
  });
  const currentPasswordVerifier = await deriveVerifier(
    reporterPassword,
    decodeBase64Url(passwordChallengeResult.data.salt),
    passwordChallengeResult.data.iterations,
  );
  const replacementPassword = "LocalIntegrationReporterChanged!2026";
  const replacementCredential = await createCredential(replacementPassword);
  const changed = await call("/api/admin/auth/change-password", {
    method: "POST", cookie: reporter.cookie, csrf: reporter.csrf,
    payload: {
      currentPasswordVerifier,
      newPasswordVerifier: replacementCredential.passwordVerifier,
      newPasswordSalt: replacementCredential.passwordSalt,
      newPasswordIterations: replacementCredential.passwordIterations,
    },
  });
  assert.match(changed.response.headers.get("set-cookie") ?? "", /Max-Age=0/u);
  await call("/api/admin/auth/me", { cookie: reporter.cookie, expected: 401 });
  assert.equal((await loginAttempt(reporterLogin, reporterPassword, 401)).status, 401);
  assert.equal((await loginAttempt(reporterLogin, replacementPassword, 200)).status, 200);
  checks.push("authenticated password change invalidates sessions and old credential");

  const oversizedBody = new ReadableStream({
    start(controller) {
      controller.enqueue(encoder.encode(`{"loginId":"${"x".repeat(81_000)}"}`));
      controller.close();
    },
  });
  const oversizedResponse = await fetch(`${base}/api/admin/auth/challenge`, {
    method: "POST",
    headers: { Origin: base, "Sec-Fetch-Site": "same-origin", "Content-Type": "application/json" },
    body: oversizedBody,
    duplex: "half",
  });
  assert.equal(oversizedResponse.status, 413);
  checks.push("chunked JSON request is rejected at the streaming byte limit");

  const lockedLogin = `locked-${suffix}`;
  const limiterIp = `2001:db8:${crypto.randomUUID().replaceAll("-", "").slice(0, 4)}:${crypto.randomUUID().replaceAll("-", "").slice(0, 4)}::2`;
  for (let attempt = 0; attempt < 8; attempt += 1) {
    await call("/api/admin/auth/login", {
      method: "POST",
      payload: { loginId: lockedLogin, passwordVerifier: "A".repeat(43) },
      expected: 401,
      ip: limiterIp,
    });
  }
  await call("/api/admin/auth/login", {
    method: "POST",
    payload: { loginId: lockedLogin, passwordVerifier: "A".repeat(43) },
    expected: 429,
    ip: limiterIp,
  });
  await call("/api/admin/auth/login", {
    method: "POST",
    payload: { loginId: lockedLogin, passwordVerifier: "A".repeat(43) },
    expected: 429,
    ip: limiterIp,
  });
  checks.push("login limiter consumes before verification and enforces the configured lock");

  for (const check of checks) console.log(`✓ ${check}`);
  console.log(`Completed ${checks.length} local HTTP integration groups.`);
}

main().catch((error) => {
  console.error(error instanceof Error ? error.stack : error);
  process.exitCode = 1;
});
