# Cloudflare Pages / D1 デプロイ手順

対象:

- Pages project: `dejikatsu-team-website`
- D1 database name: `dejikatu-website-cms`
- D1 database ID: `551309d6-b46b-4ad8-8b3a-f5340ce45f29`
- Binding variable: `CMS_DB`
- Production branch: `main`
- Preview branch: `cms`

このリポジトリのローカルコマンドは `--remote` を付けない。ローカルD1には合成データだけを使う。

## 1. Migrationを適用する

### 新規D1の場合

Cloudflare Dashboardの対象D1で **Console** を開き、次の順にファイル全体を実行する。

1. `migrations/0001_cms_schema.sql`
2. `migrations/0002_cms_hardening.sql`
3. `migrations/0003_cms_security_concurrency.sql`
4. `migrations/0004_cms_auth_retention.sql`

`0001` はCMS tableと初期4件を作る。

- 本文あり `article`: 2件
- 本文なし `legacy_link`: 2件
- PDF、参加申込、外部アプリのaction: 3件
- 初期Owner: 0件

`0002` は既存tableを壊さず、次を追加する。

- 安定した初期表示順
- fixed Owner/active credential invariant
- article state invariant
- action URL/legacy cover allowlist
- media実長、SHA-256、dimensions invariant
- slug/login ID、本文、revision、auditの制限

`0003` は認証・同時更新・Freeプラン上限に対する追加保護を行う。

- user/articleへrequest固有の `mutation_id` を追加
- active credentialのsaltを32 bytes（base64url 43文字）へ固定
- 記事本文を入力10,000文字、変換後HTML 25,000文字に制限
- 旧buildでsoft-delete済みになった未参照画像BLOBを物理削除して容量を回収
- repository管理下の既知seed本文だけsanitizer versionをv2へ更新

`0004` は認証試行行の24時間retentionを効率よく行うため、`updated_at` indexを追加する。
認証リクエストごとに古い行を最大32件だけ物理削除し、未認証botが異なるIDを試しても
`cms_login_attempts` が無期限に増え続けないようにする。

すでにschema version 2まで実行済みの場合、`0001` / `0002` を再実行せず、`0003`、`0004` の順に
それぞれ一度だけ実行する。schema version 3の場合は `0004` だけを実行する。
`0003` は `ALTER TABLE` を含むforward-only migrationであり、二重実行しない。

version 2から更新する前の確認SQL:

```sql
SELECT COUNT(*) AS invalid_active_credentials
FROM cms_users
WHERE status = 'active'
  AND (
    password_hash IS NULL OR length(password_hash) <> 43
    OR password_salt IS NULL OR length(password_salt) <> 43
    OR password_algorithm <> 'client-pbkdf2-sha256+hmac-sha256-v1'
    OR password_iterations <> 600000
  );

SELECT COUNT(*) AS oversized_articles
FROM cms_articles
WHERE length(COALESCE(body_source, '')) > 10000
   OR length(COALESCE(body_html, '')) > 25000;

SELECT COUNT(*) AS existing_mutation_columns
FROM (
  SELECT name FROM pragma_table_info('cms_users') WHERE name = 'mutation_id'
  UNION ALL
  SELECT name FROM pragma_table_info('cms_articles') WHERE name = 'mutation_id'
);
```

期待値はすべて0。0でなければ `0003` を適用せず、credential resetまたは長文記事の短縮を先に行う。

確認SQL:

```sql
SELECT value
FROM cms_schema_metadata
WHERE key = 'schema_version';

SELECT content_kind, status, COUNT(*) AS total
FROM cms_articles
GROUP BY content_kind, status;

SELECT COUNT(*) AS action_total FROM cms_article_actions;
SELECT COUNT(*) AS owner_total FROM cms_users WHERE is_fixed_owner = 1;

SELECT id, display_order
FROM cms_articles
ORDER BY display_order DESC;

SELECT COUNT(*) AS mutation_column_total
FROM (
  SELECT name FROM pragma_table_info('cms_users') WHERE name = 'mutation_id'
  UNION ALL
  SELECT name FROM pragma_table_info('cms_articles') WHERE name = 'mutation_id'
);

SELECT COUNT(*) AS login_attempts_retention_index
FROM pragma_index_list('cms_login_attempts')
WHERE name = 'cms_login_attempts_updated_idx';
```

初回Owner作成前の期待値:

```text
schema_version          4
article / published     2
legacy_link / published 2
action_total            3
owner_total             0
display_order           40, 30, 20, 10
mutation_column_total   2
login_attempts_retention_index 1
```

## 2. D1 Bindingを確認する

Cloudflare Dashboardで
**Workers & Pages → dejikatsu-team-website → Settings → Bindings** を開き、PreviewとProductionの
両方で対象D1を次の変数名へBindingする。

```text
CMS_DB
```

`wrangler.jsonc` の `database_id` はUUIDである。`database_name` はDashboardに表示される実名
`dejikatu-website-cms` と完全一致させる。IDは変更しない。

### PreviewとProductionが同じD1であることへの注意

現在の指定では `cms` Previewと `main` Productionが同じremote D1を使う。したがってPreviewでの
Owner作成、記事編集、公開停止、削除、画像upload、user作成はそのまま本番相当D1への変更になる。

- Previewでは合成テストユーザーや合成記事を作らない。
- Previewでの書込み確認は、実運用として残してよいOwner/記事だけにする。
- 将来、安全に独立したE2Eテストを行う場合はPreview専用D1とPreview専用Secretを作る。
- Preview専用D1を作らない間、Preview URLを第三者へ共有しない。

`preview_database_id` は `wrangler dev` 用であり、Pages PreviewをProduction D1から分離する設定ではない。

## 3. 暗号化Secretを追加する

**Settings → Variables and Secrets** で、PreviewとProductionの両方へ次を暗号化Secretとして追加する。
値同士を使い回さない。値はGit、`wrangler.jsonc`、issue、スクリーンショット、チャットへ書かない。

```text
CMS_BOOTSTRAP_TOKEN=<48文字以上のランダム値>
CMS_PASSWORD_PEPPER=<32バイト以上のランダム値>
CMS_AUTH_CHALLENGE_KEY=<別の32バイト以上のランダム値>
```

ローカル開発では `.dev.vars.example` を `.dev.vars` へコピーしてローカル専用値を設定する。
`.dev.vars` は `.gitignore` 対象である。

pepperを変更するときだけ、変更前の値を一時的に次へ設定する。

```text
CMS_PASSWORD_PEPPER_PREVIOUS=<直前のCMS_PASSWORD_PEPPER>
```

新しい `CMS_PASSWORD_PEPPER` で一定期間運用すると、旧pepperで成功したログイン時にD1のHMACを
現行pepperへ移行する。全ユーザー移行またはpassword reset完了後、previous Secretを削除する。
pepperを紛失しpreviousも残っていない場合、全ユーザーのpassword resetが必要になる。

## 4. Pages Buildを設定する

Pages Build System V2以降で次を使う。

```text
Build command: npm ci && npm run build
Build output directory: dist
Root directory: repository root
Node.js: 22 or later
```

`wrangler.jsonc` は `pages_build_output_dir`, compatibility date, `nodejs_compat`, `CMS_DB` を宣言する。
Wrangler設定がPages構成のsource of truthになるため、最初のPreview deploymentでBinding summaryを確認する。

ローカル検証:

```bash
npm ci
npm run types
npm run typecheck
npm test
npm run db:migrate:local
npm run build
npm run dev
```

`npm run dev` を起動したまま別terminalで、ローカル合成データだけのHTTP統合テストも行う。

```bash
node tests/local-integration.mjs
```

## 5. `cms` Previewを作る

```bash
git push origin cms
```

Pagesのdeploy完了後、Preview deploymentの次を確認する。

- source commit SHAがpushしたSHAと一致する。
- `CMS_DB` が存在する。
- 3つの必須SecretがPreviewへ存在する。
- build command/output directoryが上記と一致する。
- Functionsの例外率とCPU timeに異常がない。

コードのdeploy自体はD1へ書込みを行わない。管理画面で操作した時点で初めて書き込む。

## 6. 固定Ownerを一度だけ作る

1. `<preview-origin>/admin/setup.html` を開く。
2. bootstrap tokenをブラウザーへ直接入力する。
3. 固定OwnerのID、本名、役職、12〜128文字の固有パスワードを入力する。
4. browserがPBKDF2 600,000回を完了し、作成成功を表示するまで待つ。
5. `<preview-origin>/admin/index.html` でログインする。
6. Owner作成後、Cloudflare Dashboardから `CMS_BOOTSTRAP_TOKEN` を削除またはローテーションする。

Owner作成後の確認SQL:

```sql
SELECT login_id, real_name, job_title, role, status, is_fixed_owner,
       password_algorithm, password_iterations
FROM cms_users
WHERE is_fixed_owner = 1;
```

期待値:

```text
role                 owner
status               active
is_fixed_owner       1
password_algorithm   client-pbkdf2-sha256+hmac-sha256-v1
password_iterations  600000
```

password hash、salt、Secret、session tokenは表示・共有しない。

## 7. Preview受け入れ確認

PreviewとProductionが同じD1なので、残してよい実データだけで確認する。

1. トップページに公開4件が表示される。
2. 活動紹介ページに公開4件が表示される。
3. workshopカードからPDFと参加申込が両方動く。
4. まちの新聞カードから外部アプリが開く。
5. 本文あり2件は `/news/:slug` 専用ページを開く。
6. 専用ページ下部に他のお知らせが最大3件表示される。
7. 本名と役職が記事末尾に表示される。
8. 記事を1件作成し、太字、斜体、見出し、brand color、Markdown、任意位置画像を確認する。
9. 公開、公開停止、復元を行い、トップ、活動紹介、直接URL、関連記事へ即時反映される。
10. Reporterは自分の記事だけ操作でき、他人の記事は404/403になる。
11. Operatorはuser管理APIを使えない。
12. MasterはReporter/Operatorを管理できるがMaster role/statusを変更できない。
13. ユーザー要件どおり、Masterが別Masterの再設定URLを発行でき、対象sessionが失効する。
14. `完全削除（非推奨）` はOwner/Masterの削除済み記事だけに表示される。
15. `/admin/*` が `Cache-Control: no-store`, `X-Robots-Tag: noindex, nofollow` を返す。
16. session CookieがSecure, HttpOnly, SameSite=Strict, Path=/、Domainなしである。
17. CSRF Cookieが `__Host-cms_csrf`, Secure, SameSite=Strict, Path=/、Domainなしで、HttpOnlyなしである。
18. パスワード変更画面で現在のパスワードを再確認し、変更後に全sessionが失効して再ログインになる。
19. activation/reset URLが `#token=` を使い、画面読込み直後にaddress barから消える。
20. 最大本文、login、画像upload、`/news/:slug` のCPU timeを確認し、Freeの10msへ十分な余裕がない場合は本文上限をさらに下げるかPaidへ変更する。

Free独自認証方式では、低価格Androidや古い端末でもログイン・activation時のPBKDF2時間を測る。
Function側のHMACは軽量だが、実Cloudflare runtimeのCPU error、429率、D1書込み失敗率も確認する。

## 8. 他アカウントを作る

OwnerはMaster、Operator、Reporterを作れる。MasterはOperator、Reporterだけを新規作成できる。
CMSが返すactivation/reset URLは一度だけ表示されるため、対象本人へ安全な経路で送る。

ユーザー要件により通常Masterは別Masterのpassword reset URLを発行できる。この操作は対象sessionと
未使用tokenを失効し監査ログへ残るが、実質的なaccount takeover権限である。Masterアカウントは
少数に限定し、端末共有を避け、異常なreset監査を定期確認する。

## 9. Productionへ昇格する

Preview受け入れ完了後だけ `cms` の同一commitを `main` へmergeまたはpromoteする。

1. remote `main` SHAとdeploy source SHAを照合する。
2. ProductionのBinding/Secretを再確認する。
3. 公開API、2つの専用記事、3つのlegacy actionを確認する。
4. draft/unpublished/deletedがpublic list/detail/mediaへ出ないことを確認する。
5. FunctionsのCPU/error率とD1容量を確認する。

## 10. Backup・回復・容量管理

- 記事の通常削除はsoft delete。
- revisionは記事ごとに最新50版。
- `完全削除（非推奨）` はCMSから復元不能。
- 画像の削除は、記事から参照されていないことを同一SQLで再確認してBLOBを物理削除する。
- media uploadは全体300MB、1ユーザー100MBで原子的に停止し、Free D1の認証・監査余地を残す。
- destructive migration前はD1 exportとdeploy commit SHAを保管する。
- D1 Time TravelはDB全体の緊急復旧であり、CMSから実行しない。
- fixed Ownerは移譲・無効化・削除できない。ログインできるOwnerは管理画面の「パスワード変更」で
  現在のパスワードを再確認して変更でき、変更後は全session/tokenが失効する。
- Owner credential/pepperを失った場合は、Cloudflare DashboardでD1 backup/Time Travel地点とdeploy SHAを
  保全してから、別途監査済みの一度限りoffline回復手順を使う。通常MasterにOwner回復を許可しない。
