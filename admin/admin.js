(() => {
  'use strict';

  const page = document.body.dataset.adminPage;
  const state = { user: null, article: null, coverFile: null, coverMediaId: null, selection: null, dirty: false, articleOffset: 0, articlesHasMore: false, articleLoading: false, articleIds: new Set() };
  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
  const dataOf = (payload) => payload?.data ?? payload;
  const listOf = (payload, key) => Array.isArray(dataOf(payload)) ? dataOf(payload) : dataOf(payload)?.[key] || [];
  const roleLabel = { owner: '固定Owner', master: 'マスター', operator: 'オペレーター', reporter: 'リポーター' };

  function setStatus(target, message = '', kind = '') {
    if (!target) return;
    target.textContent = message;
    target.dataset.kind = kind;
  }
  function errorMessage(error) { return error?.message || '処理に失敗しました。時間をおいてもう一度お試しください。'; }
  const CSRF_COOKIE = '__Host-cms_csrf';
  const PASSWORD_ALGORITHM = 'client-pbkdf2-sha256+hmac-sha256-v1';
  function readCookie(name) {
    const prefix = `${name}=`;
    for (const item of document.cookie.split(';')) {
      const part = item.trim();
      if (!part.startsWith(prefix)) continue;
      const rawValue = part.slice(prefix.length);
      try { return decodeURIComponent(rawValue); } catch { return null; }
    }
    return null;
  }
  function csrfToken() {
    const value = readCookie(CSRF_COOKIE);
    return value && /^[A-Za-z0-9_-]{43}$/u.test(value) ? value : null;
  }
  async function request(path, options = {}) {
    const headers = new Headers(options.headers || {});
    if (options.body && !(options.body instanceof FormData)) headers.set('Content-Type', 'application/json');
    if (!['GET', 'HEAD'].includes((options.method || 'GET').toUpperCase())) {
      const csrf = csrfToken();
      if (csrf) headers.set('X-CSRF-Token', csrf);
      else if (state.user) throw new Error('セキュリティ情報を確認できません。ページを再読み込みしてから、もう一度お試しください。');
    }
    const response = await fetch(path, { ...options, headers, credentials: 'same-origin' });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const error = new Error(payload.error?.message || '処理に失敗しました。');
      error.status = response.status;
      error.code = payload.error?.code;
      throw error;
    }
    return payload;
  }
  function json(method, data) { return { method, body: JSON.stringify(data) }; }
  const PASSWORD_ITERATIONS = 600000;
  function bytesToBase64Url(bytes) {
    let binary = '';
    bytes.forEach((byte) => { binary += String.fromCharCode(byte); });
    return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '');
  }
  function base64UrlToBytes(value) {
    if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/u.test(value)) throw new Error('認証情報の形式が正しくありません。もう一度お試しください。');
    const padded = `${value.replaceAll('-', '+').replaceAll('_', '/')}${'='.repeat((4 - (value.length % 4)) % 4)}`;
    const binary = atob(padded);
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  }
  async function derivePasswordVerifier(password, salt, iterations) {
    const passwordLength = typeof password === 'string' ? Array.from(password).length : 0;
    if (passwordLength < 12 || passwordLength > 128) throw new Error('パスワードは12文字以上、128文字以内で入力してください。');
    if (!Number.isInteger(iterations) || iterations !== PASSWORD_ITERATIONS) throw new Error('安全な認証設定を確認できませんでした。時間をおいてもう一度お試しください。');
    const passwordKey = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
    const derived = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, passwordKey, 256);
    return bytesToBase64Url(new Uint8Array(derived));
  }
  function passwordChallenge(value) {
    const challenge = dataOf(value);
    if (challenge?.algorithm !== PASSWORD_ALGORITHM) throw new Error('安全な認証設定を確認できませんでした。時間をおいてもう一度お試しください。');
    const salt = base64UrlToBytes(challenge.salt);
    if (challenge.salt.length !== 43 || salt.byteLength !== 32) throw new Error('安全な認証設定を確認できませんでした。時間をおいてもう一度お試しください。');
    return { salt, iterations: Number(challenge.iterations) };
  }
  async function submitPassword(path, fields, report = () => {}) {
    const { password, ...otherFields } = fields;
    if (path === '/api/admin/auth/login') {
      report('認証情報を確認しています…');
      const challenge = passwordChallenge(await request('/api/admin/auth/challenge', json('POST', { loginId: otherFields.loginId })));
      report('パスワードを安全に確認しています…（数秒かかることがあります）');
      const passwordVerifier = await derivePasswordVerifier(password, challenge.salt, challenge.iterations);
      return request(path, json('POST', { loginId: otherFields.loginId, passwordVerifier }));
    }
    const salt = crypto.getRandomValues(new Uint8Array(32));
    report('パスワードを安全に設定しています…（数秒かかることがあります）');
    const passwordVerifier = await derivePasswordVerifier(password, salt, PASSWORD_ITERATIONS);
    return request(path, json('POST', {
      ...otherFields,
      passwordVerifier,
      passwordSalt: bytesToBase64Url(salt),
      passwordIterations: PASSWORD_ITERATIONS,
    }));
  }
  function redirectLogin() { location.replace('index.html'); }
  function ensurePasswordNavigation() {
    $$('.admin-nav, .admin-sidebar nav').forEach((nav) => {
      if ($('a[href="password.html"]', nav)) return;
      const link = document.createElement('a');
      link.href = 'password.html';
      link.textContent = 'パスワード変更';
      link.dataset.passwordChange = '';
      if (page === 'password') link.setAttribute('aria-current', 'page');
      const logout = $('[data-logout]', nav);
      if (logout) nav.insertBefore(link, logout); else nav.append(link);
    });
  }
  function updateIdentity() {
    $$('[data-current-user]').forEach((node) => { node.textContent = state.user ? `${state.user.realName}（${state.user.jobTitle}）` : 'ログインが必要です'; });
    const manageUsers = state.user?.role === 'owner' || state.user?.role === 'master';
    $$('[data-user-management]').forEach((node) => {
      if (manageUsers) return;
      node.classList.add('hidden');
      node.setAttribute('aria-hidden', 'true');
    });
    ensurePasswordNavigation();
  }
  async function loadMe(required = true) {
    try {
      const payload = await request('/api/admin/auth/me');
      const value = dataOf(payload);
      state.user = value.user || value;
      updateIdentity();
      return state.user;
    } catch (error) {
      if (required && error.status === 401) redirectLogin();
      throw error;
    }
  }
  function bindLogout() {
    $$('[data-logout]').forEach((button) => button.addEventListener('click', async () => {
      button.disabled = true;
      try { await request('/api/admin/auth/logout', json('POST', {})); } catch { /* expired sessions still leave this page */ }
      state.user = null;
      redirectLogin();
    }));
  }
  function navigateDashboard() { location.assign('dashboard.html'); }

  async function initLogin() {
    const form = $('[data-login-form]'); const status = $('[data-status]');
    try { if (await loadMe(false)) { navigateDashboard(); return; } } catch { /* unauthenticated is expected */ }
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      const button = $('button[type=submit]', form); button.disabled = true; setStatus(status, 'ログイン情報を準備しています…');
      try {
        const fields = new FormData(form);
        await submitPassword('/api/admin/auth/login', { loginId: fields.get('loginId'), password: fields.get('password') }, (message) => setStatus(status, message));
        await loadMe(); navigateDashboard();
      } catch (error) { setStatus(status, errorMessage(error), 'error'); button.disabled = false; }
    });
  }
  async function initSetup() {
    const form = $('[data-setup-form]'); const status = $('[data-status]');
    try {
      const setup = dataOf(await request('/api/admin/setup/status'));
      if (setup.required === false || setup.ownerExists || setup.configured) { location.replace('index.html'); return; }
    } catch (error) { setStatus(status, errorMessage(error), 'error'); }
    form.addEventListener('submit', async (event) => {
      event.preventDefault(); const button = $('button[type=submit]', form); button.disabled = true; setStatus(status, '固定Ownerを作成する準備をしています…');
      try {
        const fields = new FormData(form);
        await submitPassword('/api/admin/setup', Object.fromEntries(fields), (message) => setStatus(status, message));
        setStatus(status, '固定Ownerを作成しました。ログイン画面へ移動します。', 'success');
        setTimeout(redirectLogin, 900);
      } catch (error) { setStatus(status, errorMessage(error), 'error'); button.disabled = false; }
    });
  }
  async function initActivate() {
    const form = $('[data-activate-form]'); const status = $('[data-status]');
    const url = new URL(location.href);
    const fragment = new URLSearchParams(url.hash.startsWith('#') ? url.hash.slice(1) : '');
    const token = fragment.get('token') || url.searchParams.get('token');
    if (fragment.has('token') || url.searchParams.has('token')) {
      url.hash = '';
      url.searchParams.delete('token');
      history.replaceState(history.state, document.title, `${url.pathname}${url.search}`);
    }
    if (!token) { setStatus(status, '有効な設定リンクではありません。管理者に再発行を依頼してください。', 'error'); return; }
    form.addEventListener('submit', async (event) => {
      event.preventDefault(); const button = $('button[type=submit]', form); button.disabled = true; setStatus(status, 'パスワードを設定する準備をしています…');
      try {
        await submitPassword('/api/admin/auth/activate', { token, password: new FormData(form).get('password') }, (message) => setStatus(status, message));
        setStatus(status, 'パスワードを設定しました。ログイン画面へ移動します。', 'success');
        setTimeout(redirectLogin, 900);
      } catch (error) { setStatus(status, errorMessage(error), 'error'); button.disabled = false; }
    });
  }

  async function initPassword() {
    await loadMe(); bindLogout();
    const form = $('[data-password-form]'); const status = $('[data-status]');
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      const button = $('button[type=submit]', form);
      const fields = new FormData(form);
      const currentPassword = fields.get('currentPassword');
      const newPassword = fields.get('newPassword');
      const confirmation = fields.get('newPasswordConfirmation');
      if (newPassword !== confirmation) { setStatus(status, '新しいパスワードと確認用パスワードが一致しません。', 'error'); return; }
      button.disabled = true;
      try {
        setStatus(status, '現在の認証情報を確認しています…');
        const challenge = passwordChallenge(await request('/api/admin/auth/challenge', json('POST', { loginId: state.user.loginId })));
        setStatus(status, '現在のパスワードを安全に確認しています…（数秒かかることがあります）');
        const currentPasswordVerifier = await derivePasswordVerifier(currentPassword, challenge.salt, challenge.iterations);
        const newSalt = crypto.getRandomValues(new Uint8Array(32));
        const newPasswordSalt = bytesToBase64Url(newSalt);
        if (newPasswordSalt.length !== 43) throw new Error('安全なパスワード設定を準備できませんでした。もう一度お試しください。');
        setStatus(status, '新しいパスワードを安全に設定しています…（数秒かかることがあります）');
        const newPasswordVerifier = await derivePasswordVerifier(newPassword, newSalt, PASSWORD_ITERATIONS);
        await request('/api/admin/auth/change-password', json('POST', {
          currentPasswordVerifier,
          newPasswordVerifier,
          newPasswordSalt,
          newPasswordIterations: PASSWORD_ITERATIONS,
        }));
        form.reset(); state.user = null;
        setStatus(status, 'パスワードを変更しました。安全のため、もう一度ログインしてください。', 'success');
        setTimeout(redirectLogin, 900);
      } catch (error) {
        setStatus(status, errorMessage(error), 'error');
        button.disabled = false;
      }
    });
  }

  function dateText(value) { return value ? new Date(value).toLocaleString('ja-JP', { dateStyle: 'medium' }) : '—'; }
  function textNode(tag, text) { const node = document.createElement(tag); node.textContent = text ?? ''; return node; }
  function articleRow(article) {
    const row = document.createElement('tr');
    const title = document.createElement('a'); title.href = `editor.html?id=${encodeURIComponent(article.id)}`; title.textContent = article.title;
    const titleCell = document.createElement('td'); titleCell.dataset.label = 'タイトル'; titleCell.append(title); row.append(titleCell);
    const statusCell = document.createElement('td'); statusCell.dataset.label = '状態'; const badge = textNode('span', article.status || 'draft'); badge.className = `badge badge-${article.status || 'draft'}`; statusCell.append(badge); row.append(statusCell);
    const dateCell = textNode('td', dateText(article.publishedAt || article.createdAt)); dateCell.dataset.label = '公開日'; row.append(dateCell);
    const authorCell = textNode('td', article.authorName || article.author?.realName || '—'); authorCell.dataset.label = '作成者'; row.append(authorCell);
    const actionCell = document.createElement('td'); actionCell.dataset.label = '操作'; const edit = document.createElement('a'); edit.href = `editor.html?id=${encodeURIComponent(article.id)}`; edit.textContent = '編集'; actionCell.append(edit); row.append(actionCell);
    return row;
  }
  async function loadDashboard(reset = false) {
    const target = $('[data-articles-list]'); const status = $('[data-status]');
    const more = $('[data-load-more]');
    if (state.articleLoading) return;
    if (reset) { state.articleOffset = 0; state.articlesHasMore = false; state.articleIds.clear(); target.replaceChildren(); }
    state.articleLoading = true;
    if (more) more.disabled = true;
    try {
      const query = new URLSearchParams({ limit: '20', offset: String(state.articleOffset) });
      const value = dataOf(await request(`/api/admin/articles?${query}`));
      const articles = Array.isArray(value) ? value : value?.articles || [];
      const rows = articles.filter((article) => article?.id && !state.articleIds.has(article.id));
      rows.forEach((article) => { state.articleIds.add(article.id); target.append(articleRow(article)); });
      if (!state.articleIds.size) { const row = document.createElement('tr'); const cell = textNode('td', 'まだお知らせはありません。'); cell.colSpan = 5; cell.className = 'empty-state'; row.append(cell); target.append(row); }
      const nextOffset = Number(value?.nextOffset);
      state.articlesHasMore = value?.hasMore === true && Number.isInteger(nextOffset) && nextOffset > state.articleOffset;
      if (state.articlesHasMore) state.articleOffset = nextOffset;
      if (more) more.classList.toggle('hidden', !state.articlesHasMore);
    } catch (error) { setStatus(status, errorMessage(error), 'error'); }
    finally { state.articleLoading = false; if (more) more.disabled = false; }
  }
  async function initDashboard() {
    await loadMe(); bindLogout();
    $('[data-load-more]').addEventListener('click', () => loadDashboard());
    await loadDashboard(true);
  }

  function saveSelection() {
    const selection = window.getSelection();
    if (selection?.rangeCount) state.selection = selection.getRangeAt(0).cloneRange();
  }
  function restoreSelection(surface) {
    surface.focus(); const selection = window.getSelection();
    if (!selection) return;
    selection.removeAllRanges();
    if (state.selection && surface.contains(state.selection.commonAncestorContainer)) selection.addRange(state.selection);
    else { const range = document.createRange(); range.selectNodeContents(surface); range.collapse(false); selection.addRange(range); }
  }
  function safeUrl(url) {
    if (typeof url !== 'string' || /[\u0000-\u001F\u007F\\\\]/u.test(url) || url.startsWith('//')) return '';
    if (url.startsWith('/')) return url.startsWith('/api/media/') || url.startsWith('/news/') || url.startsWith('/activity') ? url : '';
    try {
      const parsed = new URL(url);
      return parsed.protocol === 'https:' && !parsed.username && !parsed.password ? parsed.href : '';
    } catch { return ''; }
  }
  function insertNode(surface, node) {
    restoreSelection(surface); const selection = window.getSelection(); const range = selection?.rangeCount ? selection.getRangeAt(0) : null;
    if (!range) { surface.append(node); return; }
    range.deleteContents(); range.insertNode(node); range.setStartAfter(node); range.collapse(true); selection.removeAllRanges(); selection.addRange(range); saveSelection();
  }
  function command(surface, commandName, value = null) { restoreSelection(surface); document.execCommand(commandName, false, value); saveSelection(); }
  function markdownPreview(source) {
    const fragment = document.createDocumentFragment();
    const inline = (text, target) => {
      const parts = text.split(/(\*\*[^*]+\*\*|\*[^*]+\*|\[[^\]]+\]\([^\s)]+\))/g);
      parts.forEach((part) => {
        if (part.startsWith('**') && part.endsWith('**')) { const strong = textNode('strong', part.slice(2, -2)); target.append(strong); }
        else if (part.startsWith('*') && part.endsWith('*')) { const em = textNode('em', part.slice(1, -1)); target.append(em); }
        else { const match = part.match(/^\[([^\]]+)\]\(([^\s)]+)\)$/); if (match && safeUrl(match[2])) { const a = textNode('a', match[1]); a.href = safeUrl(match[2]); a.rel = 'noopener noreferrer'; target.append(a); } else target.append(document.createTextNode(part)); }
      });
    };
    let paragraph = [];
    const flush = () => { if (!paragraph.length) return; const p = document.createElement('p'); inline(paragraph.join(' '), p); fragment.append(p); paragraph = []; };
    source.replaceAll('\r\n', '\n').split('\n').forEach((line) => {
      const heading = line.match(/^(#{1,3})\s+(.+)$/);
      if (heading) { flush(); const node = document.createElement(`h${heading[1].length}`); inline(heading[2], node); fragment.append(node); }
      else if (!line.trim()) flush(); else paragraph.push(line.trim());
    });
    flush(); return fragment;
  }
  function updatePreview() { const input = $('[data-markdown-input]'); const preview = $('[data-preview-output]'); if (!input || !preview) return; preview.replaceChildren(markdownPreview(input.value)); }
  function editorHTML(surface) {
    // The server independently sanitizes this allowlisted editor output. Remove disallowed element attributes here too.
    const clone = surface.cloneNode(true);
    clone.querySelectorAll('script,style,iframe,object,embed,form,input,button').forEach((node) => node.remove());
    clone.querySelectorAll('*').forEach((node) => {
      [...node.attributes].forEach((attribute) => {
        const allowed = (node.tagName === 'A' && ['href', 'rel'].includes(attribute.name)) || (node.tagName === 'IMG' && ['src', 'alt', 'data-media-id'].includes(attribute.name)) || (node.tagName === 'SPAN' && attribute.name === 'data-brand-color');
        if (!allowed) node.removeAttribute(attribute.name);
      });
      if (node.tagName === 'A' && !safeUrl(node.getAttribute('href') || '')) node.removeAttribute('href');
      if (node.tagName === 'IMG' && !/^\/api\/media\/[a-zA-Z0-9_-]+$/.test(node.getAttribute('src') || '')) node.remove();
    });
    return clone.innerHTML.trim();
  }
  function actionRow(action = {}) {
    const row = document.createElement('div'); row.className = 'action-row';
    const label = document.createElement('input'); label.placeholder = '表示名'; label.value = action.label || ''; label.dataset.actionLabel = '';
    const url = document.createElement('input'); url.type = 'text'; url.inputMode = 'url'; url.placeholder = 'https://… または /assets/…'; url.value = action.url || ''; url.dataset.actionUrl = '';
    const behavior = document.createElement('select'); behavior.dataset.actionBehavior = ''; [['same_tab','同じタブ'],['new_tab','新しいタブ'],['download','ダウンロード']].forEach(([value,text]) => { const option = new Option(text, value, false, (action.behavior || 'same_tab') === value); behavior.append(option); });
    const remove = document.createElement('button'); remove.type = 'button'; remove.className = 'text-button'; remove.textContent = '削除'; remove.addEventListener('click', () => { row.remove(); state.dirty = true; });
    row.append(label, url, behavior, remove); return row;
  }
  function getActions() { return $$('[data-actions-editor] .action-row').map((row, index) => ({ label: $('[data-action-label]', row).value.trim(), url: $('[data-action-url]', row).value.trim(), behavior: $('[data-action-behavior]', row).value, style: index === 0 ? 'primary' : 'secondary' })).filter((action) => action.label && action.url); }
  async function webpImage(file) {
    if (!file?.type.startsWith('image/')) throw new Error('画像ファイルを選択してください。');
    const bitmap = await createImageBitmap(file);
    const initial = Math.min(1, 1920 / Math.max(bitmap.width, bitmap.height));
    for (const scale of [initial, Math.min(initial, 1600 / Math.max(bitmap.width, bitmap.height)), Math.min(initial, 1280 / Math.max(bitmap.width, bitmap.height))]) {
      const width = Math.max(1, Math.round(bitmap.width * scale)); const height = Math.max(1, Math.round(bitmap.height * scale));
      const canvas = document.createElement('canvas'); canvas.width = width; canvas.height = height;
      canvas.getContext('2d', { alpha: false }).drawImage(bitmap, 0, 0, width, height);
      for (let quality = .9; quality >= .35; quality -= .1) {
        const blob = await new Promise((resolve) => canvas.toBlob(resolve, 'image/webp', quality));
        if (blob && blob.size <= 1500000) return { file: new File([blob], `${file.name.replace(/\.[^.]+$/, '') || 'image'}.webp`, { type: 'image/webp' }), width, height };
      }
    }
    throw new Error('画像を1.5MB以下に変換できませんでした。より小さい画像を選択してください。');
  }
  async function uploadMedia(file, alt) {
    const converted = await webpImage(file); const form = new FormData();
    form.append('image', converted.file); form.append('width', String(converted.width)); form.append('height', String(converted.height)); form.append('alt', alt || '記事内の画像');
    const media = dataOf(await request('/api/admin/media', { method: 'POST', body: form }));
    return { id: media.id, url: media.url || `/api/media/${media.id}` };
  }
  async function uploadCoverIfNeeded(status) {
    if (!state.coverFile) return state.coverMediaId;
    setStatus(status, 'アイキャッチ画像を変換・保存しています…');
    const cover = await uploadMedia(state.coverFile, $('#cover-alt').value.trim()); state.coverMediaId = cover.id; state.coverFile = null; return cover.id;
  }
  function setArticle(article) {
    state.article = article; state.coverMediaId = article.coverMediaId || article.cover?.id || null;
    const form = $('[data-article-form]');
    form.elements.articleId.value = article.id || ''; form.elements.version.value = article.version ?? ''; form.elements.contentKind.value = article.contentKind || 'article';
    ['title','subtitle','summary','category','coverAlt'].forEach((name) => { if (form.elements[name]) form.elements[name].value = article[name] || ''; });
    const surface = $('[data-editor-surface]'); surface.innerHTML = article.bodyHtml || article.body || '';
    surface.querySelectorAll('[class^="text-color-"]').forEach((node) => {
      const colour = [...node.classList].find((name) => name.startsWith('text-color-'))?.slice('text-color-'.length);
      if (['orange', 'green', 'blue'].includes(colour)) node.dataset.brandColor = colour;
    });
    // HTML-formatted records are already rendered in the editor. Do not present their HTML as Markdown.
    $('[data-markdown-input]').value = article.bodyFormat === 'markdown' ? (article.bodySource || article.markdown || '') : '';
    $('[data-markdown-toggle]').checked = article.markdownAutoConvert !== false;
    $('[data-actions-editor]').replaceChildren(...(article.actions || []).map(actionRow));
    const legacy = article.contentKind === 'legacy_link';
    $('[data-legacy-notice]').classList.toggle('hidden', !legacy); $('[data-editor-content]').classList.toggle('hidden', legacy);
    $('[data-editor-title]').textContent = '記事を編集'; $('[data-editor-lead]').textContent = legacy ? '移行済みのリンク型お知らせを編集します。' : '保存時は同時編集の衝突を検出します。';
    updateArticleControls(article);
    state.dirty = false;
  }
  function updateArticleControls(article) {
    const status = article?.status || 'new';
    const existing = Boolean(article?.id);
    const deleted = status === 'deleted';
    const published = status === 'published';
    $('[data-publish]').classList.toggle('hidden', !existing || deleted || published);
    $('[data-unpublish]').classList.toggle('hidden', !existing || deleted || !published);
    $('[data-soft-delete]').classList.toggle('hidden', !existing || deleted);
    $('[data-restore]').classList.toggle('hidden', !existing || !deleted);
    $('[data-permanent-delete]').classList.toggle('hidden', !existing || !deleted || !['owner', 'master'].includes(state.user?.role));
  }
  function articlePayload() {
    const form = $('[data-article-form]'); const legacy = form.elements.contentKind.value === 'legacy_link'; const surface = $('[data-editor-surface]');
    const content = editorHTML(surface);
    if (!legacy && !surface.textContent.trim() && !surface.querySelector('img')) throw new Error('本文を入力してください。');
    const markdownSource = legacy ? '' : $('[data-markdown-input]').value.trim();
    const bodyFormat = legacy ? 'none' : (markdownSource ? 'markdown' : 'html');
    return { id: form.elements.articleId.value || undefined, version: form.elements.version.value ? Number(form.elements.version.value) : undefined, contentKind: form.elements.contentKind.value, title: form.elements.title.value.trim(), subtitle: form.elements.subtitle.value.trim(), summary: form.elements.summary.value.trim(), category: form.elements.category.value.trim(), coverAlt: form.elements.coverAlt.value.trim(), coverMediaId: state.coverMediaId || undefined, bodyHtml: legacy ? undefined : content, bodySource: bodyFormat === 'markdown' ? markdownSource : undefined, bodyFormat, markdownAutoConvert: $('[data-markdown-toggle]').checked, actions: getActions() };
  }
  async function saveArticle() {
    const status = $('[data-status]'); const payload = articlePayload(); setStatus(status, '保存しています…'); await uploadCoverIfNeeded(status); payload.coverMediaId = state.coverMediaId || undefined;
    const result = dataOf(await request(payload.id ? `/api/admin/articles/${encodeURIComponent(payload.id)}` : '/api/admin/articles', json(payload.id ? 'PATCH' : 'POST', payload)));
    setArticle(result.article || result); setStatus(status, '保存しました。', 'success'); return state.article;
  }
  async function sendArticleAction(action, success) {
    const status = $('[data-status]'); const id = state.article?.id || $('[data-article-form]').elements.articleId.value; if (!id) { setStatus(status, '先に記事を保存してください。', 'error'); return; }
    setStatus(status, '処理しています…'); const result = dataOf(await request(`/api/admin/articles/${encodeURIComponent(id)}${action}`, json(action === '/permanent' ? 'DELETE' : action ? 'POST' : 'DELETE', {})));
    if (action === '/permanent') { state.dirty = false; setStatus(status, '完全削除しました。', 'success'); setTimeout(navigateDashboard, 600); return; }
    setArticle(result.article || result); setStatus(status, success, 'success');
  }
  async function initEditor() {
    await loadMe(); bindLogout(); const form = $('[data-article-form]'); const status = $('[data-status]'); const surface = $('[data-editor-surface]');
    const markdownInput = $('[data-markdown-input]');
    const markdownHelp = document.createElement('small');
    markdownHelp.textContent = 'Markdown欄に内容がある場合はMarkdown原文を正本として保存し、本文表示を再生成します。上のリッチ本文を正本にする場合は、この欄を空にしてください。';
    markdownInput.insertAdjacentElement('afterend', markdownHelp);
    const id = new URLSearchParams(location.search).get('id');
    if (id) { try { const result = dataOf(await request(`/api/admin/articles/${encodeURIComponent(id)}`)); setArticle(result.article || result); } catch (error) { setStatus(status, errorMessage(error), 'error'); } }
    else $('[data-actions-editor]').replaceChildren();
    form.addEventListener('input', () => { state.dirty = true; });
    form.addEventListener('change', () => { state.dirty = true; });
    window.addEventListener('beforeunload', (event) => { if (state.dirty) { event.preventDefault(); event.returnValue = ''; } });
    surface.addEventListener('keyup', saveSelection); surface.addEventListener('mouseup', saveSelection); surface.addEventListener('input', saveSelection);
    $$('[data-format]').forEach((button) => button.addEventListener('mousedown', (event) => { event.preventDefault(); const format = button.dataset.format; if (format === 'h2' || format === 'h3') command(surface, 'formatBlock', format); else if (['orange','green','blue'].includes(format)) { const span = document.createElement('span'); span.dataset.brandColor = format; const selection = window.getSelection(); if (selection?.rangeCount && !selection.isCollapsed) { const range = selection.getRangeAt(0); span.append(range.extractContents()); range.insertNode(span); } } else if (format === 'link') { const value = prompt('リンク先URLを入力してください。'); if (value && safeUrl(value)) command(surface, 'createLink', safeUrl(value)); } else command(surface, format); state.dirty = true; saveSelection(); }));
    $('[data-markdown-apply]').addEventListener('click', () => { surface.replaceChildren(markdownPreview($('[data-markdown-input]').value)); state.dirty = true; saveSelection(); });
    $('[data-preview]').addEventListener('click', updatePreview); $('[data-markdown-input]').addEventListener('input', () => { if ($('[data-markdown-toggle]').checked) { updatePreview(); surface.replaceChildren(markdownPreview($('[data-markdown-input]').value)); saveSelection(); } });
    $('[data-add-action]').addEventListener('click', () => { $('[data-actions-editor]').append(actionRow()); state.dirty = true; });
    $('[data-insert-image]').addEventListener('click', () => $('[data-inline-image]').click());
    $('[data-inline-image]').addEventListener('change', async (event) => { const file = event.target.files[0]; if (!file) return; const alt = prompt('画像の説明（代替テキスト）を入力してください。'); if (!alt?.trim()) { setStatus(status, '画像を追加するには、画像の説明（代替テキスト）が必要です。', 'error'); event.target.value = ''; return; } try { setStatus(status, '記事内画像を変換・保存しています…'); const media = await uploadMedia(file, alt.trim()); const image = document.createElement('img'); image.src = media.url; image.alt = alt.trim(); image.dataset.mediaId = media.id; insertNode(surface, image); state.dirty = true; setStatus(status, '画像を本文に追加しました。', 'success'); } catch (error) { setStatus(status, errorMessage(error), 'error'); } finally { event.target.value = ''; } });
    $('#cover-file').addEventListener('change', (event) => { state.coverFile = event.target.files[0] || null; setStatus($('[data-cover-status]'), state.coverFile ? '保存時にWebPへ変換してアップロードします。' : ''); });
    form.addEventListener('submit', async (event) => { event.preventDefault(); const button = $('button[type=submit]', form); button.disabled = true; try { await saveArticle(); } catch (error) { setStatus(status, errorMessage(error), 'error'); } finally { button.disabled = false; } });
    $('[data-publish]').addEventListener('click', async () => { try { await saveArticle(); await sendArticleAction('/publish', '公開しました。'); } catch (error) { setStatus(status, errorMessage(error), 'error'); } });
    $('[data-unpublish]').addEventListener('click', async () => { if (state.dirty && !confirm('未保存の変更があります。変更を破棄して公開を停止しますか？')) return; try { await sendArticleAction('/unpublish', '公開を停止しました。'); } catch (error) { setStatus(status, errorMessage(error), 'error'); } });
    $('[data-soft-delete]').addEventListener('click', async () => { const warning = state.dirty ? '\n未保存の変更は破棄されます。' : ''; if (confirm(`この記事を削除しますか？公開サイトには表示されなくなります。${warning}`)) try { await sendArticleAction('', '削除しました。'); } catch (error) { setStatus(status, errorMessage(error), 'error'); } });
    $('[data-restore]').addEventListener('click', async () => { try { await sendArticleAction('/restore', '記事を復元しました。'); } catch (error) { setStatus(status, errorMessage(error), 'error'); } });
    const permanent = $('[data-permanent-delete]'); if (['owner','master'].includes(state.user.role)) { permanent.addEventListener('click', async () => { const warning = state.dirty ? '\n未保存の変更は破棄されます。' : ''; if (confirm(`完全削除（非推奨）を実行しますか？この操作は元に戻せません。${warning}`)) try { await sendArticleAction('/permanent', '完全削除しました。'); } catch (error) { setStatus(status, errorMessage(error), 'error'); } }); }
    updateArticleControls(state.article);
  }

  function canEditUserProfile(target) {
    if (!state.user) return false;
    if (state.user.role === 'owner') return target.role !== 'owner' || target.id === state.user.id;
    return state.user.role === 'master' && target.role !== 'owner';
  }
  function canChangeUserAccess(target) {
    if (!state.user) return false;
    if (state.user.role === 'owner') return target.role !== 'owner';
    return state.user.role === 'master' && !['owner','master'].includes(target.role);
  }
  async function copyOneTimeUrl(value, status) {
    const url = value?.activationUrl || value?.resetUrl || value?.url; if (!url) { setStatus(status, '有効化リンクを取得できませんでした。', 'error'); return; }
    try { await navigator.clipboard.writeText(url); setStatus(status, '一回限りのリンクをコピーしました。安全な方法で本人に送ってください。', 'success'); }
    catch { setStatus(status, `リンク: ${url}`, 'success'); }
  }
  async function loadUsers() {
    const target = $('[data-users-list]'); const status = $('[data-status]');
    try {
      const users = listOf(await request('/api/admin/users'), 'users'); target.replaceChildren();
      users.forEach((user) => {
        const profileEditable = canEditUserProfile(user);
        const accessEditable = canChangeUserAccess(user);
        const row = document.createElement('tr'); const profile = document.createElement('td'); profile.dataset.label = '氏名・役職';
        const name = document.createElement(profileEditable ? 'input' : 'strong');
        if (profileEditable) { name.value = user.realName || ''; name.maxLength = 100; name.ariaLabel = `${user.loginId}の氏名`; } else name.textContent = user.realName;
        const title = document.createElement(profileEditable ? 'input' : 'span');
        if (profileEditable) { title.value = user.jobTitle || ''; title.maxLength = 100; title.ariaLabel = `${user.loginId}の役職`; } else title.textContent = user.jobTitle;
        profile.append(name, document.createElement('br'), title); const loginCell = textNode('td', user.loginId); loginCell.dataset.label = 'ID'; row.append(profile, loginCell);
        const role = document.createElement('td'); role.dataset.label = '権限'; let roleSelect;
        if (accessEditable) { roleSelect = document.createElement('select'); ['reporter','operator','master'].forEach((value) => { if (state.user.role !== 'owner' && value === 'master') return; roleSelect.append(new Option(roleLabel[value], value, false, user.role === value)); }); role.append(roleSelect); } else role.append(textNode('span', roleLabel[user.role] || user.role)); row.append(role);
        const statusCell = document.createElement('td'); statusCell.dataset.label = '状態'; let statusSelect;
        if (accessEditable) {
          statusSelect = document.createElement('select');
          const statuses = user.status === 'pending' ? ['pending', 'disabled'] : ['active', 'disabled'];
          const labels = { pending: '有効化待ち', active: '有効', disabled: '無効' };
          statuses.forEach((value) => statusSelect.append(new Option(labels[value], value, false, user.status === value)));
          statusCell.append(statusSelect);
        } else statusCell.textContent = ({ pending: '有効化待ち', active: '有効', disabled: '無効' })[user.status] || user.status;
        row.append(statusCell);
        const action = document.createElement('td'); action.dataset.label = '操作';
        if (profileEditable) { const save = document.createElement('button'); save.type = 'button'; save.className = 'text-button'; save.textContent = '保存'; save.addEventListener('click', async () => { try { await request(`/api/admin/users/${encodeURIComponent(user.id)}`, json('PATCH', { realName: name.value.trim(), jobTitle: title.value.trim(), role: accessEditable ? roleSelect.value : user.role, status: accessEditable ? statusSelect.value : user.status, version: user.version })); setStatus(status, `${name.value}さんのアカウントを更新しました。`, 'success'); await loadUsers(); } catch (error) { setStatus(status, errorMessage(error), 'error'); } }); action.append(save); }
        if (accessEditable || (state.user.role === 'master' && user.role === 'master' && user.id !== state.user.id)) { const reset = document.createElement('button'); reset.type = 'button'; reset.className = 'text-button'; reset.textContent = '再設定リンク'; reset.addEventListener('click', async () => { try { await copyOneTimeUrl(dataOf(await request(`/api/admin/users/${encodeURIComponent(user.id)}/reset-password`, json('POST', {}))), status); } catch (error) { setStatus(status, errorMessage(error), 'error'); } }); action.append(reset); }
        row.append(action); target.append(row);
      });
      if (!users.length) { const row = document.createElement('tr'); const cell = textNode('td', 'アカウントがありません。'); cell.colSpan = 5; cell.className = 'empty-state'; row.append(cell); target.append(row); }
    } catch (error) { setStatus(status, errorMessage(error), 'error'); }
  }
  async function initUsers() {
    await loadMe(); bindLogout(); if (!['owner','master'].includes(state.user.role)) { location.replace('dashboard.html'); return; }
    if (state.user.role === 'master') { const masterOption = $('#new-role option[value=master]'); if (masterOption) masterOption.remove(); }
    const form = $('[data-create-user-form]'); const status = $('[data-create-status]');
    form.addEventListener('submit', async (event) => { event.preventDefault(); const button = $('button[type=submit]', form); button.disabled = true; try { const result = dataOf(await request('/api/admin/users', json('POST', Object.fromEntries(new FormData(form))))); await copyOneTimeUrl(result, status); form.reset(); await loadUsers(); } catch (error) { setStatus(status, errorMessage(error), 'error'); } finally { button.disabled = false; } });
    await loadUsers();
  }

  const run = async () => {
    try {
      if (page === 'login') await initLogin(); else if (page === 'setup') await initSetup(); else if (page === 'activate') await initActivate(); else if (page === 'password') await initPassword(); else if (page === 'dashboard') await initDashboard(); else if (page === 'editor') await initEditor(); else if (page === 'users') await initUsers();
    } catch (error) { const status = $('[data-status]'); if (status) setStatus(status, errorMessage(error), 'error'); else console.error(error); }
  };
  run();
})();
