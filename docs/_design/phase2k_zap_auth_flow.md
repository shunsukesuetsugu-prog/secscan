# Phase 2-K 設計案: ZAP auth-flow context (login → session → 保護リソース probe)

Phase 2-J (active mode) で unauthenticated な攻撃面 (SQLi / XSS / auth bypass) は捕捉できるようになりますが、**ログイン後のみアクセス可能な脆弱性** — IDOR、権限昇格、session fixation など — は依然として漏れます。Phase 2-K は ZAP に **login context** を渡してログイン状態でスキャンする経路を加えます。

## ゴール

1. **`secscan dast --zap-context <path>`** で ZAP context XML を受け取れるようにする (`--zap-config-file` の延長)。
2. **Juice Shop の auth-flow context** を `bench/fixtures/dast/juice-shop/auth-flow.context` として committed。bench がそれを使って認証後スキャンを実行できる。
3. **認証後の expected pluginid** を `expected_authflow_findings` として fixture に追加 (IDOR / 権限昇格 / authenticated CSRF など)。
4. **`bench/run.py --dast-authflow`** flag で opt-in。`--dast-active` と独立 (両方つけると 3 種 scan を順次実行)。

## 既存 secscan invariants (前提・再評価不要)

- subprocess shell=False + argv list
- ZAP image digest pin
- volume create → chown → scan → cat → rm の 5-step lifecycle
- `--cap-drop=ALL --security-opt=no-new-privileges`
- helper image alpine digest pin
- target URL は http/https のみ、private/loopback は warning
- bench fixture path は SAFE_FIXTURE_ROOT 配下のみ

## ZAP context file の構造

ZAP の context は XML で、以下を含む:

```xml
<configuration>
  <context>
    <name>juice-shop-auth</name>
    <urlparser><class>...</class></urlparser>
    <urls>
      <regex>http://host\.docker\.internal:[0-9]+/.*</regex>
    </urls>
    <authentication>
      <type>3</type>  <!-- 3 = form-based -->
      <form-based>
        <login-url>http://host.docker.internal:PORT/rest/user/login</login-url>
        <login-body>{"email":"admin@juice-sh.op","password":"admin123"}</login-body>
        <login-content-type>application/json</login-content-type>
      </form-based>
    </authentication>
    <users>
      <user>
        <name>juice-shop-admin</name>
        <credentials>email=admin@juice-sh.op,password=admin123</credentials>
        <enabled>true</enabled>
      </user>
    </users>
  </context>
</configuration>
```

Juice Shop の admin credentials は OWASP の公式 documentation 公開値 (`admin@juice-sh.op` / `admin123`)。テスト fixture なので、これは bench 専用かつ Juice Shop 専用の認証情報。

**security 上の留意点**:
- context XML 内に **実 credential が平文で存在する** → 該当 fixture は **secscan/gitleaks の scan 対象から除外する**設計が必要
- `.secscan.toml` の `ignore` に `bench/fixtures/dast/*/auth-flow.context` を追加
- README で「これらは test target 専用の合成 credential」を明示

## ZAP の `-z` 引数

zap-baseline.py / zap-full-scan.py は `-z` flag で context file を受け取れる:

```
zap-baseline.py -t URL -J report.json -z "-config replacer.full_list(0).description=..."
```

または `-n <context_file>` で context file を直接読み込む。

Phase 2-K の secscan 側は:

- `secscan dast --zap-context <path>` を新規追加
- 既存 `--zap-config-file` (汎用 config) と別の独立 option
- `report_volume` への bind mount に context file も同居させて container 内で読ませる

## 期待するレビュー観点 (3 点)

1. **context file 内の credential 漏洩**: bench fixture 内に admin@juice-sh.op/admin123 を commit する。これは Juice Shop の公式 example だが secscan 自体の `secrets` scanner が反応する可能性。除外パスや allowlist で吸収する設計
2. **ZAP context は volume に乗せる際の path 問題**: 既存の `/zap/wrk` volume に context file を `cp` 経由で入れるか、別 helper container で書き込むか
3. **`--zap-context` の path validation**: 任意 path 指定で `/etc/passwd` 等が読まれる余地がないか — DastInputError で再検証

## 期待形式

- Markdown 表で観点 → 指摘 → 推奨
- 各指摘 80 字以内
- 既存 invariants は前提として再評価不要

## Phase 2-K のスコープ外 (後回し)

- 認証 token の自動取得 → ZAP の standard form-auth で間に合う
- multi-step login (CAPTCHA / 2FA) → 後回し
- WebGoat の auth-flow → Juice Shop で動いてから検討
