import { type Env, esc } from "../lib/cms";

type Row = {
  id: string;
  slug: string;
  content_kind: "article" | "legacy_link";
  title: string;
  subtitle: string;
  summary: string;
  category: string;
  body_html: string | null;
  cover_media_id: string | null;
  legacy_cover_path: string | null;
  cover_alt: string;
  published_at: string;
  author_name_snapshot: string;
  author_job_title_snapshot: string;
};

const ARTICLE_COLUMNS = `
  id, slug, content_kind, title, subtitle, summary, category, body_html,
  cover_media_id, legacy_cover_path, cover_alt, published_at,
  author_name_snapshot, author_job_title_snapshot
`;

function displayDate(value: string): string {
  return new Intl.DateTimeFormat("ja-JP", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    timeZone: "Asia/Tokyo",
  })
    .format(new Date(value))
    .replaceAll("/", ".");
}

function coverUrl(row: Pick<Row, "cover_media_id" | "legacy_cover_path">): string {
  return row.cover_media_id ? `/api/media/${row.cover_media_id}` : (row.legacy_cover_path ?? "");
}

function relatedHref(row: Pick<Row, "id" | "slug" | "content_kind">): string {
  return row.content_kind === "article"
    ? `/news/${encodeURIComponent(row.slug)}`
    : `/activity.html#activity-${encodeURIComponent(row.id)}`;
}

function relatedCard(item: Row): string {
  const cover = coverUrl(item);
  return `<a class="related-card" href="${esc(relatedHref(item))}">
    ${cover ? `<img src="${esc(cover)}" alt="${esc(item.cover_alt)}" loading="lazy">` : ""}
    <div>
      <time datetime="${esc(item.published_at)}">${displayDate(item.published_at)}</time>
      <h3>${esc(item.title)}</h3>
      <span>${item.content_kind === "article" ? "記事を読む" : "活動紹介を見る"} →</span>
    </div>
  </a>`;
}

function page(article: Row, related: Row[]): string {
  const cover = coverUrl(article);
  return `<!doctype html>
<html lang="ja">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="${esc(article.summary)}">
    <title>${esc(article.title)}｜デジ活チーム</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Noto+Sans+JP:wght@400;500;600;700;800;900&family=Zen+Kaku+Gothic+New:wght@500;700;900&display=swap" rel="stylesheet">
    <link rel="icon" type="image/png" href="/assets/dejikatsu-logo-cutout.png">
    <link rel="stylesheet" href="/campaign.css">
    <link rel="stylesheet" href="/news.css">
  </head>
  <body>
    <header class="header">
      <a class="brand header-brand" href="/">
        <img class="site-logo" src="/assets/dejikatsu-logo-cutout.png" alt="デジ活チーム">
        <span class="brand-domain">dejikatu.com</span>
      </a>
      <button class="menu-button" type="button" aria-expanded="false" aria-controls="site-nav">
        <span></span><span></span><span></span><span class="sr-only">メニューを開く</span>
      </button>
      <nav id="site-nav" class="nav" aria-label="メインナビゲーション">
        <a href="/about.html">デジ活チームとは</a>
        <a class="active" href="/activity.html">活動紹介</a>
        <a href="/#members">メンバー</a>
      </nav>
    </header>
    <main>
      <section class="article-hero">
        <div class="article-hero-inner">
          <a class="article-back" href="/activity.html">← 活動紹介へ戻る</a>
          <p class="article-category">${esc(article.category)}</p>
          <h1 class="article-title">${esc(article.title)}</h1>
          ${article.subtitle ? `<p class="article-subtitle">${esc(article.subtitle)}</p>` : ""}
          <time class="article-date" datetime="${esc(article.published_at)}">${displayDate(article.published_at)}</time>
        </div>
      </section>
      <article class="news-article">
        <div class="news-article-inner">
          ${cover ? `<img class="article-cover" src="${esc(cover)}" alt="${esc(article.cover_alt)}">` : ""}
          <div class="article-content">${article.body_html ?? ""}</div>
          <footer class="article-author">
            <span class="article-author-mark" aria-hidden="true">D</span>
            <div>
              <p>この記事を書いた人</p>
              <strong>${esc(article.author_name_snapshot)}</strong>
              <span>${esc(article.author_job_title_snapshot)}</span>
            </div>
          </footer>
        </div>
      </article>
      <section class="related-news" aria-labelledby="related-title">
        <div class="related-news-inner">
          <p class="eyebrow">MORE NEWS</p>
          <h2 id="related-title">ほかのお知らせ</h2>
          <div class="related-grid">${related.map(relatedCard).join("")}</div>
        </div>
      </section>
    </main>
    <footer class="footer">
      <a class="brand" href="/"><img class="site-logo" src="/assets/dejikatsu-logo-cutout.png" alt="デジ活チーム"></a>
      <p>デジタルを架け橋に、次の世代へつながる地域コミュニティを。</p>
      <div>
        <a href="/about.html">デジ活チームとは</a>
        <a href="/activity.html">活動紹介</a>
        <a href="https://forms.gle/oKjVMFrYi4kWfYpR7" target="_blank" rel="noopener">参加・お問い合わせ</a>
      </div>
      <small>@ 2026 DEJIKATU TEAM</small>
    </footer>
    <script src="/script.js"></script>
  </body>
</html>`;
}

function securityHeaders(contentType: string): HeadersInit {
  return {
    "content-type": contentType,
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
    "content-security-policy": [
      "default-src 'self'",
      "script-src 'self'",
      "img-src 'self'",
      "style-src 'self' https://fonts.googleapis.com",
      "font-src https://fonts.gstatic.com",
      "object-src 'none'",
      "frame-ancestors 'none'",
      "base-uri 'none'",
      "form-action 'self'",
      "upgrade-insecure-requests",
    ].join("; "),
  };
}

export const onRequest: PagesFunction<Env> = async (context) => {
  if (context.request.method !== "GET" && context.request.method !== "HEAD") {
    return new Response("Method Not Allowed", {
      status: 405,
      headers: { ...securityHeaders("text/plain; charset=UTF-8"), allow: "GET, HEAD" },
    });
  }

  const slug = String(context.params.slug ?? "");
  const article = await context.env.CMS_DB.prepare(
    `SELECT ${ARTICLE_COLUMNS}
     FROM cms_articles
     WHERE slug = ?
       AND content_kind = 'article'
       AND status = 'published'
       AND published_at IS NOT NULL
       AND deleted_at IS NULL`,
  )
    .bind(slug)
    .first<Row>();

  if (!article) {
    return new Response("記事が見つかりません。", {
      status: 404,
      headers: securityHeaders("text/plain; charset=UTF-8"),
    });
  }

  const related = (
    await context.env.CMS_DB.prepare(
      `SELECT ${ARTICLE_COLUMNS}
       FROM cms_articles
       WHERE status = 'published'
         AND published_at IS NOT NULL
         AND deleted_at IS NULL
         AND id <> ?
       ORDER BY published_at DESC, display_order DESC, id
       LIMIT 3`,
    )
      .bind(article.id)
      .all<Row>()
  ).results;

  return new Response(context.request.method === "HEAD" ? null : page(article, related), {
    headers: securityHeaders("text/html; charset=UTF-8"),
  });
};
