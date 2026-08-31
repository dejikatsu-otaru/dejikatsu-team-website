# CMS API contract

同一オリジンの Cloudflare Pages Functions と、Binding名 `CMS_DB` の専用D1を前提とする。
成功JSONは `{ "data": ... }`、失敗JSONは
`{ "error": { "code": "...", "message": "..." }, "requestId": "..." }` とする。
管理API、認証API、公開記事API、画像はすべて `Cache-Control: no-store` とし、公開停止を即時反映する。

## 公開API

- `GET|HEAD /api/public/articles?limit=4&exclude=<id>`
  - `status='published' AND published_at IS NOT NULL AND deleted_at IS NULL` の記事だけを返す。
  - `limit` は1〜20。範囲外は400。
- `GET|HEAD /api/public/articles/:slug`
  - 本文を持つ公開記事1件と、同じ公開条件の関連記事を最大3件返す。
- `GET|HEAD /api/media/:id`
  - 公開記事が参照するD1 WebP BLOBを返す。
  - 非公開画像は、管理権限を持つログイン済みユーザーだけが取得できる。
- `GET|HEAD /news/:slug`
  - 既存サイトと同じヘッダー、フッター、色、書体を使う専用記事ページを返す。

公開カードは `id`, `slug`, `contentKind`, `title`, `subtitle`, `summary`, `category`,
`coverUrl`, `coverAlt`, `publishedAt`, `detailUrl`, `actions` を持つ。`legacy_link` の
`detailUrl` は `null` であり、トップページからは活動紹介ページ内の該当カードへ移動する。

Action URLは保存時と出力時の両方で検証する。許可するのは次だけである。

- `https://` の外部URL（userinfoを含まない）
- `/assets/` から始まる同一サイトのファイル

`javascript:`, `data:`, `vbscript:`, `//host`, 制御文字、改行、NUL、バックスラッシュ、
dot segmentを含む値は拒否する。外部リンクは `rel="noopener noreferrer"` を付ける。
`legacy_cover_path` も `/assets/` 配下だけを許可する。

## Freeプラン用認証方式

Workers FreeのHTTPリクエストCPU上限内でサーバー側PBKDF2 600,000回を実行できないため、
ユーザーの明示承認に基づき次の独自方式を採用する。

```text
V = PBKDF2-HMAC-SHA-256(password, perUserSalt, 600000, 256 bit)  // browser
stored = HMAC-SHA-256(CMS_PASSWORD_PEPPER, V)                    // Function
```

`V` はbase64urlで送る。D1に保存するのはHMAC結果、個別salt、iteration数、algorithm名だけで、
生パスワードと `V` は保存しない。ブラウザーも password、salt、`V` をWeb Storageへ保存せず、
ログにも出力しない。

この方式では、通信・XSS・拡張機能・ログ等から `V` が漏れた場合、`V` 自体が再利用可能な
パスワード相当値になる。標準的なサーバーKDFやPAKEではない。また
`CMS_PASSWORD_PEPPER` を失うと全アカウントの再設定が必要になる。この残存リスクは、
Freeプランを維持する判断として明示的に受容されている。

必要な暗号化Secret:

- `CMS_BOOTSTRAP_TOKEN`: 初回Owner作成専用。一度使った後は削除またはローテーションする。
- `CMS_PASSWORD_PEPPER`: 現行HMAC pepper。32バイト以上のランダム値。
- `CMS_AUTH_CHALLENGE_KEY`: fake saltとrate-limit scopeのHMAC用。pepperとは独立した値。
- `CMS_PASSWORD_PEPPER_PREVIOUS`: pepperローテーション中だけ任意で設定する旧値。

pepperローテーション中は現行値、旧値の順に検証する。旧値で成功したログインは、受信した
`V` を現行pepperで再HMACしD1を更新する。移行完了後は previous Secretを削除する。

## 認証API

- `GET|HEAD /api/admin/setup/status`
- `POST /api/admin/setup`
  - `bootstrapToken`, `loginId`, `realName`, `jobTitle`, `passwordVerifier`,
    `passwordSalt`, `passwordIterations`
  - 固定Ownerが0件の間だけ成功する。Owner作成と監査ログをD1 batchで処理する。
- `POST /api/admin/auth/challenge`
  - `loginId`
  - 実在する有効ユーザーには個別saltを返す。存在しない、無効、未有効化、旧方式のIDには
    `HMAC(CMS_AUTH_CHALLENGE_KEY, normalizedLoginId)` 由来の決定論的fake saltを返す。
  - status、body形式、iteration数は同一にし、アカウント存在の判別材料を減らす。
- `POST /api/admin/auth/login`
  - `loginId`, `passwordVerifier`
- `GET|HEAD /api/admin/auth/me`
  - 現在ユーザーだけを返す。GETでCSRF tokenをrotateしない。
- `POST /api/admin/auth/logout`
- `POST /api/admin/auth/activate`
  - one-time `token`, `passwordVerifier`, `passwordSalt`, `passwordIterations`
  - activationとreset-passwordの共通完了endpoint。
- `POST /api/admin/auth/change-password`
  - 認証済み本人だけが `currentPasswordVerifier`, `newPasswordVerifier`, `newPasswordSalt`,
    `newPasswordIterations` を送る。
  - 現在credential、CSRF、Originを再確認し、password更新、全session/token失効、監査を同じ条件付きbatchで行う。
  - 成功後はCookieを削除して再ログインさせる。fixed Ownerもこの本人用経路を使える。

challengeはIPと正規化IDごと、login失敗もIPと正規化IDごとに独立制限する。scopeは
`CMS_AUTH_CHALLENGE_KEY` でHMACし、D1へ生IPや生login IDを保存しない。challengeは15分間に
60回、login失敗は15分間に8回を上限とし、超過後15分間ロックする。各認証リクエストでは
24時間更新されていない試行行を、`updated_at` indexを使って最大32件だけ削除する。

このD1制限はアカウント総当たりと行の無期限増加を抑えるが、D1へ到達する前のedge遮断ではない。
Pages FunctionsのWrangler設定では現在Rate Limiting bindingを指定できないため、custom domainを使える場合は
Cloudflareのzone側rate limiting ruleを `/api/admin/auth/*` と `/api/admin/setup*` に追加する。
`pages.dev` だけで運用する場合、分散botがWorkers/D1 Freeの日次上限を消費し得ることを残存リスクとして
監視し、429、Functions request数、D1 rows writtenの急増時には一時的に管理APIを遮断する。

session tokenとCSRF tokenは各32ランダムバイト。D1にはSHA-256結果だけを保存する。
session Cookieは `__Host-cms_session; Secure; HttpOnly; SameSite=Strict; Path=/`、Domain属性なし。
CSRF tokenは `__Host-cms_csrf; Secure; SameSite=Strict; Path=/`、Domain属性なし、HttpOnlyなしのCookieにも
保持し、same-origin JSだけが読んで `X-CSRF-Token` へ複写する。serverはD1のhashと比較する。
idle timeoutは30分、absolute timeoutは8時間。各リクエストでsessionと現在のuser status/roleを
JOINして再確認する。logout、activation、password reset、role/status変更では対象sessionを全失効する。

activation/reset URLは `/admin/activate.html#token=...` とする。fragmentはHTTP request、Referer、通常の
invocation URLへ送信されず、画面は読取り直後に `history.replaceState` でaddress barから除去する。

すべてのstate-changing endpointは次を要求する。

- JSON、または画像だけ `multipart/form-data`
- request URLと完全一致する `Origin`
- `Sec-Fetch-Site` が `cross-site` ではないこと
- 認証後の操作は現在sessionの `X-CSRF-Token`

JSON bodyはstreamを80,000 bytesまで読み、超過時はreaderをcancelして413を返す。画像multipartは
1,750,000 bytesまでに制限してからparseする。`Content-Length` だけには依存しない。

## 記事API

- `GET|HEAD /api/admin/articles?limit=20&offset=0`
  - `limit` は1〜20。21件目で `hasMore` と `nextOffset` を返す。
  - actionは記事ごとのN+1 queryを行わず、page内article IDの `IN (...)` 1 queryで取得する。
- `POST /api/admin/articles`
  - 新規作成できるのは本文を持つ `article` だけ。
  - title、summary、category、coverAlt、本文が必須。slugはサーバーが衝突しにくい値を生成する。
- `GET|HEAD /api/admin/articles/:id`
- `PATCH /api/admin/articles/:id`
  - `version` 必須。stale writeは409。
  - 移行済み `legacy_link` はmetadataとactionsだけ編集でき、種類や本文は変更できない。
- `DELETE /api/admin/articles/:id`: soft delete
- `POST /api/admin/articles/:id/publish`
- `POST /api/admin/articles/:id/unpublish`
- `POST /api/admin/articles/:id/restore`
- `DELETE /api/admin/articles/:id/permanent`
  - Owner/Masterだけ。UI表記は `完全削除（非推奨）`。

Markdownはbrowserで自動変換できるが、serverでも本文形式に従ってレンダリングし、必ず
`sanitize-html` の明示allowlistへ通す。HTML形式も同じallowlistへ通す。raw HTML、script、form、
iframe、event属性、inline style、外部画像を許可しない。本文画像は
`/api/media/<UUID>` だけ、色は `orange`, `green`, `blue`, `navy` のclassだけを許可する。
本文入力は10,000文字、sanitize後HTMLは25,000文字を上限とする。これはFree WorkerのCPU 10msへ
余裕を持たせるための上限であり、PreviewのCPU計測で余裕がなければさらに下げる。
変更ごとにrevisionを保存し、D1容量保護のため各記事の最新50版を保持する。

記事本体のoptimistic updateは `version` とrequest固有 `mutation_id` を使う。revision、本文画像、
legacy action、監査は同じ `mutation_id` の勝者だけが書き込めるため、同時PATCHの敗者は副作用なしで409になる。

Reporterのownershipは記事・画像のSQL条件で確認し、`created_by` はtriggerで不変とする。
Reporterは自分の記事を作成、編集、公開、公開停止、soft-delete、復元できる。

## 画像API

- `POST /api/admin/media`
  - `multipart/form-data`: `image`, `width`, `height`, `alt`
- `GET|HEAD /api/admin/media?limit=50&offset=0`
- `DELETE /api/admin/media/:id`

browserはCanvas再エンコードでmetadataを落とし、WebP、長辺1920px以下、1.5MB以下へ変換する。
serverはclient申告を信用せず、RIFF実長、WEBP、VP8/VP8L/VP8X chunk、実dimensions、単一画像、
metadata/animation chunk不在、最大1920×1920、最大3,686,400 pixels、1.5MB以下を検証する。
VP8X canvasと実payload dimensionsを別々に解析して一致を要求し、重複VP8X/payload、予約flag、
不正なchunk順序も拒否する。
D1 triggerは `length(data)=byte_size` とserver計算SHA-256の長さも検証する。

Free D1の500MB全体を画像で埋めないため、mediaは全体300MB、1ユーザー100MBでuploadを停止する。
quota判定とINSERTは単一の `INSERT ... SELECT ... WHERE` で原子的に行う。画像削除はcover/body参照の
不存在とReporter所有権をDELETE statement自体で確認し、BLOBを物理削除する。upload/delete監査は
実際の勝者だけが残る。認証・監査用に約200MBの余地を予約する保守的上限である。

## ユーザーと権限

- `GET|HEAD /api/admin/users`
- `POST /api/admin/users`: pending userとone-time activation URLを作る。
- `PATCH /api/admin/users/:id`: 許可された氏名、役職、status、roleを変更する。正整数の `version` 必須。
- `POST /api/admin/users/:id/reset-password`: 旧session/tokenを失効しone-time URLを作る。
- `GET|HEAD /api/admin/audit`: Owner/Master向けread-only監査ログ。

権限表:

- 固定Owner: 全操作。移譲、降格、無効化、削除は不可。
- Master: 全記事・画像操作。Reporter/Operatorの作成・管理。Masterの追加・権限変更・無効化は不可。
  Masterの氏名・役職だけは編集可能。ユーザーの明示要件により、別の通常Masterのpassword reset URL発行だけは可能。
- Operator: 全記事・画像操作。権限・アカウント操作は不可。
- Reporter: 自分の記事・画像の作成、編集、公開、公開停止、soft-delete、復元。
- 記事の物理削除はOwner/Masterだけ。

通常Masterから別Masterへのpassword resetは、対象Masterのsessionを全失効し、監査ログへ残すが、
実質的には水平account takeover権限である。これはユーザーが明示指定した例外であり、通常の
推奨権限設計より強いリスクを持つ。

user PATCHは `version` とrequest固有 `mutation_id` を使い、権限境界をUPDATE SQLにも再記述する。
role/status変更時のsession/token失効とbefore/after role/status/version監査は、同じmutation勝者だけが実行する。
activation/reset tokenは元hashをrequest固有claim hashへ条件付きで変更し、同時利用では正確に1requestだけが
credentialを変更できる。`activate` はpendingだけをactive化し、`reset_password` は現在statusを変更しない。
