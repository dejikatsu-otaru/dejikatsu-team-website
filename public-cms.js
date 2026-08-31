(() => {
  const endpoint = '/api/public/articles?limit=20';
  const formatDate = (value) => {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? '' : date.toLocaleDateString('ja-JP', { year: 'numeric', month: '2-digit', day: '2-digit', timeZone: 'Asia/Tokyo' }).replaceAll('/', '.');
  };
  const element = (tag, className, text) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  };
  const linkAttributes = (anchor, action) => {
    if (action.behavior === 'new_tab') {
      anchor.target = '_blank';
      anchor.rel = 'noopener noreferrer';
    }
    if (action.behavior === 'download') anchor.download = '';
  };
  const makeCover = (article) => {
    const image = document.createElement('img');
    image.src = article.coverUrl || 'assets/dejikatsu-logo-cutout.png';
    image.alt = article.coverAlt || '';
    image.loading = 'lazy';
    return image;
  };
  const viewLabel = (article) => article.contentKind === 'article' ? '記事を読む →' : '詳細・申込を見る →';
  const createNewsCard = (article) => {
    const href = article.detailUrl || `activity.html#activity-${encodeURIComponent(article.id)}`;
    const card = document.createElement('a');
    card.className = 'news-card';
    card.href = href;
    card.append(makeCover(article));
    const copy = element('div');
    const date = element('time', '', formatDate(article.publishedAt));
    date.dateTime = article.publishedAt || '';
    copy.append(date, element('p', '', article.title), element('span', '', viewLabel(article)));
    card.append(copy);
    return card;
  };
  const createActivityCard = (article) => {
    const card = element('article', 'activity-card');
    card.id = `activity-${article.id}`;
    card.append(makeCover(article));
    const copy = element('div', 'activity-card-copy');
    const date = element('time', '', formatDate(article.publishedAt));
    date.dateTime = article.publishedAt || '';
    copy.append(date, element('p', 'activity-category', article.category || 'お知らせ'), element('h3', 'activity-card-title', article.title));
    if (article.subtitle) copy.append(element('p', 'activity-subtitle', article.subtitle));
    copy.append(element('p', '', article.summary || ''));
    const actions = element('div', 'article-actions');
    if (article.detailUrl) {
      const read = element('a', 'article-read', '記事を読む →');
      read.href = article.detailUrl;
      actions.append(read);
    }
    (article.actions || []).forEach((action) => {
      const anchor = element('a', action.style === 'primary' ? 'article-apply' : '', action.label);
      anchor.href = action.url;
      linkAttributes(anchor, action);
      actions.append(anchor);
    });
    if (actions.childElementCount) copy.append(actions);
    card.append(copy);
    return card;
  };
  const showState = (target, state, message) => {
    target.replaceChildren(element('p', `cms-${state}`, message));
  };
  const load = async () => {
    const newsTarget = document.querySelector('[data-public-news]');
    const activityTarget = document.querySelector('[data-public-activity]');
    if (!newsTarget && !activityTarget) return;
    try {
      const response = await fetch(endpoint, { headers: { Accept: 'application/json' } });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload.error?.message || '読み込みに失敗しました。');
      const articles = Array.isArray(payload.data) ? payload.data : payload.data?.articles || [];
      if (newsTarget) {
        if (articles.length) newsTarget.replaceChildren(...articles.slice(0, 4).map(createNewsCard));
        else showState(newsTarget, 'empty', '現在公開中のお知らせはありません。');
        window.initializeNewsCarousels?.();
      }
      if (activityTarget) {
        if (articles.length) activityTarget.replaceChildren(...articles.map(createActivityCard));
        else showState(activityTarget, 'empty', '現在公開中の活動情報はありません。');
      }
    } catch (error) {
      const message = 'お知らせを読み込めませんでした。時間をおいて再度お試しください。';
      if (newsTarget) { showState(newsTarget, 'error', message); window.initializeNewsCarousels?.(); }
      if (activityTarget) showState(activityTarget, 'error', message);
      console.warn('CMS public articles failed to load.', error);
    }
  };
  load();
})();
