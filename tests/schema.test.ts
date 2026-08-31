import { applyD1Migrations, env, type D1Migration } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";

declare global {
  namespace Cloudflare {
    interface Env {
      TEST_MIGRATIONS: D1Migration[];
    }
  }
}

beforeAll(async () => {
  await applyD1Migrations(env.CMS_DB, env.TEST_MIGRATIONS);
});

describe("CMS D1 schema", () => {
  const credentialHash = "h".repeat(43);
  const credentialSalt = "s".repeat(43);

  it("seeds two full articles, two legacy cards and three legacy actions", async () => {
    const articleCounts = await env.CMS_DB.prepare(
      "SELECT content_kind, status, COUNT(*) AS total FROM cms_articles GROUP BY content_kind, status ORDER BY content_kind",
    ).all<{ content_kind: string; status: string; total: number }>();
    const actionCount = await env.CMS_DB.prepare(
      "SELECT COUNT(*) AS total FROM cms_article_actions",
    ).first<{ total: number }>();

    expect(articleCounts.results).toEqual([
      { content_kind: "article", status: "published", total: 2 },
      { content_kind: "legacy_link", status: "published", total: 2 },
    ]);
    expect(actionCount?.total).toBe(3);
  });

  it("preserves the PDF, application and external-service destinations", async () => {
    const actions = await env.CMS_DB.prepare(
      "SELECT label, url, behavior FROM cms_article_actions ORDER BY id",
    ).all<{ label: string; url: string; behavior: string }>();

    expect(actions.results).toEqual([
      {
        label: "利用はこちらから",
        url: "https://machi-shinbun.com/",
        behavior: "new_tab",
      },
      {
        label: "参加申込",
        url: "https://forms.gle/QkLGtUSfmZuz7pK17",
        behavior: "new_tab",
      },
      {
        label: "PDFをダウンロード",
        url: "/assets/第２回ワークショップチラシ（町会役員バージョン）.pdf",
        behavior: "download",
      },
    ]);
  });

  it("starts without a credential or Owner row", async () => {
    const owner = await env.CMS_DB.prepare(
      "SELECT COUNT(*) AS total FROM cms_users WHERE is_fixed_owner = 1",
    ).first<{ total: number }>();
    expect(owner?.total).toBe(0);
  });

  it("applies all hardening migrations and stable initial ordering", async () => {
    const version = await env.CMS_DB.prepare(
      "SELECT value FROM cms_schema_metadata WHERE key = 'schema_version'",
    ).first<{ value: string }>();
    const order = await env.CMS_DB.prepare(
      "SELECT display_order FROM cms_articles ORDER BY display_order DESC",
    ).all<{ display_order: number }>();

    const userMutationColumn = await env.CMS_DB.prepare(
      "SELECT COUNT(*) AS total FROM pragma_table_info('cms_users') WHERE name = 'mutation_id'",
    ).first<{ total: number }>();
    const articleMutationColumn = await env.CMS_DB.prepare(
      "SELECT COUNT(*) AS total FROM pragma_table_info('cms_articles') WHERE name = 'mutation_id'",
    ).first<{ total: number }>();

    expect(version?.value).toBe("4");
    expect(order.results.map((row) => row.display_order)).toEqual([40, 30, 20, 10]);
    expect(userMutationColumn?.total).toBe(1);
    expect(articleMutationColumn?.total).toBe(1);
  });

  it("indexes authentication-attempt retention", async () => {
    const index = await env.CMS_DB.prepare(
      "SELECT COUNT(*) AS total FROM pragma_index_list('cms_login_attempts') WHERE name = 'cms_login_attempts_updated_idx'",
    ).first<{ total: number }>();
    expect(index?.total).toBe(1);
  });

  it("allows exactly one fixed Owner and prevents demotion, disabling or deletion", async () => {
    await env.CMS_DB.prepare(
      `INSERT INTO cms_users (
        id, login_id, real_name, job_title, role, status, is_fixed_owner,
        password_hash, password_salt, password_algorithm, password_iterations, password_changed_at
      ) VALUES (?, ?, ?, ?, 'owner', 'active', 1, ?, ?, 'client-pbkdf2-sha256+hmac-sha256-v1', 600000, ?)` ,
    )
      .bind("usr_owner_test", "owner-test", "固定所有者", "代表", credentialHash, credentialSalt, "2026-08-31T00:00:00.000Z")
      .run();

    await expect(
      env.CMS_DB.prepare(
        `INSERT INTO cms_users (
          id, login_id, real_name, job_title, role, status, is_fixed_owner,
          password_hash, password_salt, password_algorithm, password_iterations
        ) VALUES ('usr_owner_second', 'owner-second', '二人目', '代表', 'owner', 'active', 1, ?, ?,
          'client-pbkdf2-sha256+hmac-sha256-v1', 600000)`,
      ).bind(credentialHash, credentialSalt).run(),
    ).rejects.toThrow();

    await expect(
      env.CMS_DB.prepare("UPDATE cms_users SET role = 'master', is_fixed_owner = 0 WHERE id = ?")
        .bind("usr_owner_test")
        .run(),
    ).rejects.toThrow();

    await expect(
      env.CMS_DB.prepare("UPDATE cms_users SET status = 'disabled' WHERE id = ?")
        .bind("usr_owner_test")
        .run(),
    ).rejects.toThrow();

    await expect(
      env.CMS_DB.prepare("DELETE FROM cms_users WHERE id = ?").bind("usr_owner_test").run(),
    ).rejects.toThrow(/fixed_owner_cannot_be_deleted/);
  });

  it("keeps article ownership and content kind immutable", async () => {
    await env.CMS_DB.prepare(
      `INSERT INTO cms_users (id, login_id, real_name, job_title, role, status)
       VALUES ('usr_reporter_test', 'reporter-test', '記者', '広報', 'reporter', 'pending')`,
    ).run();

    await expect(
      env.CMS_DB.prepare("UPDATE cms_articles SET created_by = ? WHERE id = ?")
        .bind("usr_reporter_test", "art_digital_course_20260819")
        .run(),
    ).rejects.toThrow(/article_owner_immutable/);

    await expect(
      env.CMS_DB.prepare("UPDATE cms_articles SET content_kind = 'article' WHERE id = ?")
        .bind("art_workshop_20260819")
        .run(),
    ).rejects.toThrow(/article_content_kind_immutable/);
  });

  it("enforces the D1 image storage ceiling and WebP-only policy", async () => {
    await expect(
      env.CMS_DB.prepare(
        `INSERT INTO cms_media (
          id, owner_user_id, original_name, mime_type, byte_size, width, height, sha256, data
        ) VALUES ('med_too_large', 'usr_reporter_test', 'large.webp', 'image/webp', 1500001, 1920, 1080, 'hash', ?)` ,
      )
        .bind(new Uint8Array([82, 73, 70, 70, 0, 0, 0, 0, 87, 69, 66, 80]))
        .run(),
    ).rejects.toThrow();

    await expect(
      env.CMS_DB.prepare(
        `INSERT INTO cms_media (
          id, owner_user_id, original_name, mime_type, byte_size, width, height, sha256, data
        ) VALUES ('med_png', 'usr_reporter_test', 'image.png', 'image/png', 12, 100, 100, 'hash', ?)` ,
      )
        .bind(new Uint8Array([137, 80, 78, 71]))
        .run(),
    ).rejects.toThrow();
  });

  it("keeps audit records append-only", async () => {
    await env.CMS_DB.prepare(
      `INSERT INTO cms_audit_logs (
        id, request_id, actor_user_id, actor_role, action, target_type, target_id, outcome
      ) VALUES ('aud_test', 'req_test', NULL, NULL, 'schema.test', 'system', NULL, 'success')`,
    ).run();

    await expect(
      env.CMS_DB.prepare("UPDATE cms_audit_logs SET action = 'tampered' WHERE id = 'aud_test'").run(),
    ).rejects.toThrow(/audit_log_is_append_only/);
    await expect(
      env.CMS_DB.prepare("DELETE FROM cms_audit_logs WHERE id = 'aud_test'").run(),
    ).rejects.toThrow(/audit_log_is_append_only/);
  });

  it("rejects active passwordless users and unsafe stored action URLs", async () => {
    await expect(
      env.CMS_DB.prepare(
        `INSERT INTO cms_users (id, login_id, real_name, job_title, role, status)
         VALUES ('usr_passwordless', 'passwordless', '無効な利用者', '広報', 'reporter', 'active')`,
      ).run(),
    ).rejects.toThrow(/invalid_user_security_state/);

    await expect(
      env.CMS_DB.prepare(
        `INSERT INTO cms_users (
          id, login_id, real_name, job_title, role, status,
          password_hash, password_salt, password_algorithm, password_iterations
        ) VALUES ('usr_short_salt', 'short-salt', '無効な利用者', '広報', 'reporter', 'active', ?, ?,
          'client-pbkdf2-sha256+hmac-sha256-v1', 600000)`,
      ).bind(credentialHash, "s".repeat(22)).run(),
    ).rejects.toThrow(/invalid_user_security_state/);

    await expect(
      env.CMS_DB.prepare(
        `INSERT INTO cms_article_actions (id, article_id, label, url, behavior, style, sort_order)
         VALUES ('act_xss', 'art_workshop_20260819', '危険', 'javascript:alert(1)', 'same_tab', 'primary', 99)`,
      ).run(),
    ).rejects.toThrow(/unsafe_article_action_url/);
  });

  it("rejects inconsistent article and media states", async () => {
    await expect(
      env.CMS_DB.prepare(
        "UPDATE cms_articles SET published_at = NULL WHERE id = 'art_digital_course_20260819'",
      ).run(),
    ).rejects.toThrow(/invalid_article_security_state/);

    await expect(
      env.CMS_DB.prepare(
        `INSERT INTO cms_media (
          id, owner_user_id, original_name, mime_type, byte_size, width, height, sha256, data
        ) VALUES ('med_bad_length', 'usr_reporter_test', 'bad.webp', 'image/webp', 1, 1, 1, ?, ?)`,
      ).bind("x".repeat(43), new Uint8Array([1, 2])).run(),
    ).rejects.toThrow(/invalid_media_integrity/);

    await expect(
      env.CMS_DB.prepare(
        "UPDATE cms_articles SET body_source = ? WHERE id = 'art_digital_course_20260819'",
      ).bind("x".repeat(10_001)).run(),
    ).rejects.toThrow(/invalid_article_security_state/);

    await expect(
      env.CMS_DB.prepare(
        "UPDATE cms_articles SET body_html = ? WHERE id = 'art_digital_course_20260819'",
      ).bind(`<p>${"x".repeat(25_001)}</p>`).run(),
    ).rejects.toThrow(/invalid_article_security_state/);
  });
});
