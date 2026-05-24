# Phase 2-D 設計案: DAST (OWASP ZAP) 対応

これは secscan (Python製の脆弱性検査CLI) に DAST スキャナーを追加する設計のドラフトです。実装は未着手。Codex / 他モデル に向けたレビュー用ドキュメントです。

## 既存 secscan の invariants (前提・再評価不要)

- subprocess は `shell=False` + argv list で実行
- `Finding.raw` / `raw_fingerprint` は外部出力に含めない
- stderr / message は `redact_text` → `truncate` の順
- path は `ResolvedRoot.contains` で再検証 (path traversal 阻止)
- `ScanOutcome.warnings` で非致命情報を伝達
- baseline は `(fingerprint, scanner, rule_id)` で照合
- fingerprint は cross-tool 互換が必要 (GHSA → CVE → URL → id の優先順位)
- 出力フォーマッタは text / json / sarif の 3 種、`--quiet` は text のみ
- `SECSCAN_CI=1` で baseline accept を CI で禁止
- redaction: REDACTED トークン + AWS/GitHub/Slack/npm_/pypi-/UV_INDEX*/URL basic-auth/JWT

## Phase 2-D スコープ

`secscan dast --target <URL>` で OWASP ZAP の baseline scan を起動し、結果を正規化 Finding に変換する。

## 起動方式 (MVP)

- Docker 経由のみ: `zaproxy/zap-stable` イメージ
- **イメージは SHA256 digest でピン留め必須** (GLM 1 次指摘: タグは可変で supply chain risk)
  - デフォルト digest を `secscan/scanners/dast/_pinned.py` で定数化、`--zap-image` で上書き可能
  - digest が省略形 (`@sha256:abc...` 不在) なら起動拒否
- **image ref validator** (Codex 2 次指摘反映):
  - 形式は `^[a-z0-9][a-z0-9._\-/]*(:[a-zA-Z0-9._\-]+)?@sha256:[0-9a-f]{64}$` のみ許可
  - **先頭が `-` で始まる image ref は拒否** (flag injection 防止)
  - OCI image ref として最低限の構文 (repository + optional tag + digest) を必須化
- argv (例 / `--` 区切り):
  ```
  ["docker", "run", "--rm", "--cap-drop=ALL", "--network=bridge", "-t",
   "--", "zaproxy/zap-stable@sha256:<digest>",
   "zap-baseline.py", "-t", "<URL>", "-J", "/dev/stdout"]
  ```
- **`docker run <opts> -- <image> <cmd>` の `--` セパレータ必須** (Codex 2 次指摘: `--zap-image` 値が flag 化する余地を遮断)
- **`--cap-drop=ALL` を必ず付与** (GLM 1 次指摘)
- **`--network=bridge` をデフォルト**、`--zap-network host` を明示した場合のみ host 解放
- Docker socket は **マウントしない**
- ローカル ZAP CLI 直叩きは Phase 2-D-late に回す
- レポートは `-J /dev/stdout` で stdout 取得

## CLI 設計

- `--target <URL>` (必須): http:// または https:// のみ
- `--ajax-spider` (任意): JS-heavy サイト向け
- `--config-file <path>` (任意): ZAP context file path
- `--zap-image <ref>` (任意): デフォルト `zaproxy/zap-stable`、digest 指定推奨
- `--timeout-seconds <int>` (任意): デフォルト 600s
- 既存 `--format text|json|sarif`, `--output`, `--baseline`, `--fail-on` と統合

## 安全性

- URL scheme check: http/https のみ許可、それ以外は `ValueError`
- 内部ネットワーク (10/8, 192.168/16, 172.16/12, 169.254/16, 127/8, localhost, .local) の場合は **warning を発行して継続** (DAST 用途として正当な場合もあるため)
- Docker subprocess は argv list で `shell=False`
- ZAP 出力 JSON の URL / evidence / param 文字列は redact → truncate を通す
- **外部出力での host 再構成は一切しない** (Codex 2 次指摘):
  - SARIF / JSON / text どの format でも target_host を出力に再構成して埋め込まない
  - `Finding.location.url` は内部表現としてのみ保持 (raw に近い)
  - 公開フィールドは下記「URI 正規化」ルールで `dast/<encoded-path>` 形式に変換
- Docker socket は **マウントしない**

## URI 正規化 (外部出力用、Codex 2 次指摘反映)

外部出力 (SARIF artifactLocation.uri / JSON location.url / text 表示) では:

- 形式: `dast/<urlencoded-path>` 相対 URI
  - 例: `https://example.com/api/users?id=1` → `dast/%2Fapi%2Fusers`
  - path の `/`, `..`, `:` を percent-encode して階層越えを完全に潰す
  - query / fragment は URI からは除外、`Finding.message` 側に redacted 形で記述
- host は出力しない (target_host は scan 全体に紐づく属性として `RunResult.metadata.dast_target` に 1 度だけ載せる、これは secscan-json v2 で導入予定)
- Phase 2-D MVP の `secscan-json v1` 出力では host を完全省略

## 出力マッピング

ZAP alert 1 件 → 1 Finding:

- `scanner` = `"dast"`
- `rule_id` = ZAP `pluginid` (整数文字列、例 `"10038"`)
- `title` = alert `name`
- `severity`: `High` → HIGH, `Medium` → MEDIUM, `Low` → LOW, `Informational` → INFO, それ以外 → UNKNOWN
- `message` = alert `description` (redact → truncate)
- `location.url` = alert `url` (発生 URL)
- `cwe` = `cweid` if present (CWE-xxxx)
- `references` = alert `reference` を URL 抽出して http(s) のみ最大 5 件

## ZAP JSON パース時の必須フィールド検証 (GLM 1 次指摘反映)

公式スキーマがなくバージョン間で非互換のため、必須フィールドの存在検証を実施:

- top-level に `site` (list) があること、`site[i].alerts` (list) があること
- 各 alert に `pluginid` (str/int)、`name` (str)、`riskdesc`/`risk` (str) のいずれかがあること
- いずれも欠落していれば該当 alert を `outcome.warnings` に積んで skip (raise ではなく)
- ZAP のバージョンを `site[i].@version` から拾えれば `RunResult.metadata` (将来追加) に乗せる検討

## fingerprint 設計 (GLM + Codex 反映の最終版)

```
sha256("dast" + "\0" + pluginid + "\0" + target_host + "\0" + url_path + "\0" + sorted_query_keys + "\0" + param_token)
```

- target_host は `--target` の正規化済み host (lowercase, port 込み)
- url_path は alert URL から path のみを取り、query/fragment を除く
- **sorted_query_keys**: alert URL の query string の key のみ (値は除く) を sort + join
- **param_token** (Codex 2 次指摘反映: param の null/空/配列正規化):
  - `param` が **None / 欠落 / 空文字**: センチネル `"NO_PARAM"` を使用
  - `param` が `str`: そのまま使用 (前後 whitespace strip)
  - `param` が `list`: 各要素を str 化 → strip → 空除外 → sort → unique → `","` で join
  - `param` がその他の型 (dict/int 等): `outcome.warnings` に `"unexpected dast param type"` を積み、`"NO_PARAM"` にフォールバック
- **param 有無の baseline 二重化対策** (Codex 2 次指摘): 同じ (pluginid, path) で「param あり」「param なし」が両方報告された場合、coarse-key (`pluginid, path, NO_PARAM`) と fine-key (`pluginid, path, param_token`) の両方を fingerprint インデックスに記録し、`baseline accept` がどちらの粒度でもヒットするよう照合する。
  - 実装: `Finding.fingerprint` は fine-key (主)、`Finding.fingerprint_aliases: tuple[str, ...]` (新フィールド) に coarse-key を入れる
  - baseline 側は `(fingerprint or fingerprint_aliases) ∩ baseline_entries` で照合
- evidence は fingerprint に含めない

## ZAP param 型仕様の前提

Codex 2 次レビュー指摘: ZAP の `param` フィールドの型は公式仕様で確認できていない (**不明**)。観測ベースでは大半が str、ごく一部のプラグインで配列を返す可能性がある。

上記 `param_token` 正規化は防御的に実装し、想定外の型は warning として観測可能にする。

## レビュー反映履歴

### GLM 5.1 1 次レビュー (反映済み)

1. ✅ ZAP JSON 必須フィールド検証を追加 + image digest pinning
2. ✅ `--cap-drop=ALL` + `--network=bridge` デフォルト
3. ✅ fingerprint に query_keys + param_name を含めるよう設計変更

### Codex 2 次レビュー (反映済み)

1. ✅ Docker argv に `--` セパレータ必須化
2. ✅ image ref validator (先頭 `-` 拒否、OCI 形式必須)
3. ✅ 外部出力での host 再構成を全 format で禁止
4. ✅ URI 正規化を `dast/<urlencoded-path>` 相対形式に統一
5. ✅ param_token 正規化 (`NO_PARAM` センチネル、配列 sort+unique、想定外型 warning)
6. ✅ `fingerprint_aliases` で coarse/fine 両 key を baseline 照合に登録

## Kimi reconfirm 観点

「Codex の 8 指摘 (Docker argv ×2 / URL 出力 ×3 / fingerprint ×3) がすべて設計に反映されているか」のみ機械的に確認すれば OK。新規観点は不要。
