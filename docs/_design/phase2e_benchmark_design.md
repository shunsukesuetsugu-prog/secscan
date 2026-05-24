# Phase 2-E 設計案: 検知率ベンチマーク

「secscan は脆弱性をどれぐらい検知できるか」を**再現可能な数値**で示すための仕組み。

## ゴール

1. **scanner ごとの recall (検出率)** を計測 — known-vulnerable fixture に対する検出数 / 既知の脆弱性数
2. **業界比較** — 同じ fixture を npm-audit / pip-audit / gitleaks 単体で走らせて、secscan の上乗せ価値を可視化
3. **CI 走行可能 (DAST 除く)** — fixtures は repo に含め、subprocess fake は使わず実際のツールチェーンで走らせる
4. **Markdown レポート自動生成** — `bench/report.md` (人間用) + `bench/report.json` (機械用)

## 非ゴール (明示的に範囲外)

- **OWASP Benchmark Project (Java) のような重量級スイート**: secscan は Java 非対応、含めない
- **絶対精度の保証**: 「semgrep の特定 ruleset × fixture」の組み合わせ結果であり、ruleset を変えれば結果も変わる。**ベンチマーク = 回帰テストの代替**として位置づける
- **商用ツール比較 (Snyk / GHAS)**: ライセンス上不可

## 既存 secscan invariants (前提・再評価不要)

- subprocess は shell=False + argv list
- `Finding.raw` / `raw_fingerprint` は外部に出さない
- redact_text → truncate
- ResolvedRoot.contains で path 再検証
- baseline (fingerprint, scanner, rule_id) 照合
- SECSCAN_CI=1 で baseline accept 禁止

## ディレクトリ構成

```
bench/
├── README.md                      # 走らせ方
├── run.py                         # 計測ランナー
├── compare.py                     # 業界ツールとの比較ランナー
├── fixtures/
│   ├── deps/
│   │   ├── npm-vulnerable/        # package.json + package-lock.json (既知 GHSA をピン)
│   │   │   ├── package.json
│   │   │   ├── package-lock.json
│   │   │   └── expected.json      # 検知すべき GHSA リスト
│   │   ├── pnpm-vulnerable/
│   │   ├── yarn-vulnerable/
│   │   ├── pip-vulnerable/
│   │   └── uv-vulnerable/
│   ├── secrets/
│   │   ├── synthetic/             # 自前 fixture: 合成だが正規表現にマッチする無効トークン
│   │   │   ├── aws_invalid.txt
│   │   │   ├── github_pat_invalid.txt
│   │   │   ├── slack_invalid.txt
│   │   │   ├── npm_token_invalid.txt
│   │   │   └── expected.json
│   │   └── clean/                 # 誤検出測定用: 普通のソースコード
│   │       ├── normal_python.py
│   │       └── expected.json      # findings: []
│   ├── sast/
│   │   ├── python/
│   │   │   ├── cwe78_cmd_injection.py
│   │   │   ├── cwe89_sql_injection.py
│   │   │   ├── cwe502_yaml_load.py
│   │   │   ├── cwe798_hardcoded.py
│   │   │   ├── clean.py
│   │   │   └── expected.json
│   │   └── javascript/
│   │       ├── cwe78_cmd_injection.js
│   │       ├── cwe502_eval.js
│   │       ├── clean.js
│   │       └── expected.json
│   └── dast/                      # DAST は重いので "optional" カテゴリ
│       └── juice-shop/
│           ├── docker-compose.yml # OWASP Juice Shop を 127.0.0.1:3000 で起動
│           └── expected.json      # 検知すべき ZAP pluginid リスト
├── report.md                      # run.py で再生成 (このファイルは出力先)
└── report.json
```

### fixture の作り方

#### deps (npm の例)

```json
// package.json
{
  "name": "secscan-bench-npm",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "lodash": "4.17.20",
    "minimist": "1.2.5"
  }
}
```

`package-lock.json` は実際に `npm install --package-lock-only` で生成（フローズン）。

```json
// expected.json
{
  "ecosystem": "npm",
  "expected_findings": [
    {"advisory_id": "GHSA-35jh-r3h4-6jhm", "package": "lodash", "severity": "HIGH"},
    {"advisory_id": "GHSA-xvch-5gv4-984h", "package": "minimist", "severity": "MEDIUM"}
  ],
  "notes": "Both GHSAs are stable in the npm advisory db as of design time."
}
```

#### secrets (合成テストデータ)

実トークン形状にマッチするが、絶対に有効でないトークン (チェックサム失敗または既に revoke 済みの公開サンプル) を使う。

```
// aws_invalid.txt
# Synthetic AWS access key — checksum invalid; for benchmark only.
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

```json
// expected.json
{
  "expected_findings": [
    {"rule_id_pattern": "aws-access-token", "file": "aws_invalid.txt"},
    {"rule_id_pattern": "aws-secret-access-key", "file": "aws_invalid.txt"}
  ]
}
```

#### sast (CWE 単機能 fixture)

各 fixture は **1 つの CWE 1 件**の意図的脆弱性 + 期待される rule_id (semgrep) のリスト。

```python
# cwe78_cmd_injection.py
import subprocess

def run_user_command(user_input):
    # CWE-78: shell=True with user input
    subprocess.run(user_input, shell=True)
```

```json
// expected.json (python ディレクトリ全体)
{
  "expected_findings": [
    {"file": "cwe78_cmd_injection.py", "cwe": "CWE-78", "min_severity": "MEDIUM"},
    {"file": "cwe89_sql_injection.py", "cwe": "CWE-89", "min_severity": "MEDIUM"},
    {"file": "cwe502_yaml_load.py", "cwe": "CWE-502", "min_severity": "MEDIUM"},
    {"file": "cwe798_hardcoded.py", "cwe": "CWE-798", "min_severity": "MEDIUM"}
  ]
}
```

#### dast (OWASP Juice Shop)

```yaml
# bench/fixtures/dast/juice-shop/docker-compose.yml
services:
  juice-shop:
    image: bkimminich/juice-shop:v17.0.0  # digest pinning は別 PR
    ports:
      - "127.0.0.1:3000:3000"
```

`expected.json` は最初の実行で生成される ZAP alert pluginid のスナップショット (regression baseline)。**初回は手動で精査して**「これらは確かに Juice Shop の意図的脆弱性」とマークし、以降の run はこの集合に対して recall を計算。

## マッチング仕様

### deps

- secscan の Finding `rule_id` (= GHSA/CVE) と `expected.advisory_id` を一致比較
- 大文字小文字無視
- 検知率 = 一致した期待 GHSA 数 / 期待 GHSA 数

### secrets

- secscan Finding の `rule_id` が `expected.rule_id_pattern` に部分一致 (例: `"aws-"` で `aws-access-token` も `aws-iam-unique-id` もマッチ)
- 同じ file に複数 expected がある場合、それぞれ別カウント

### sast

- Finding の `cwe` フィールド (CWE-xx) と `expected.cwe` を比較
- `min_severity` 以上の検知のみカウント (低 severity の補足検知は recall に含めない)

### dast

- Finding `rule_id` (= ZAP pluginid) と `expected.pluginid` リストを比較

### clean fixture (precision 測定)

- `expected_findings: []` のディレクトリで Finding が出たら **誤検出**
- precision = (true positives) / (true positives + false positives) ← scanner 全体で集計

## 業界比較

`bench/compare.py` が以下を実行:

| Tool | Command | Fixture |
|---|---|---|
| `npm audit` | `npm audit --json` | bench/fixtures/deps/npm-vulnerable |
| `pip-audit` | `pip-audit -r requirements.txt -f json` | bench/fixtures/deps/pip-vulnerable |
| `gitleaks` | `gitleaks dir bench/fixtures/secrets/synthetic` | bench/fixtures/secrets/synthetic |
| `semgrep` | `semgrep --config p/python --json bench/fixtures/sast/python` | bench/fixtures/sast/python |

それぞれの **finding 数** を抽出し、secscan の同 fixture 結果と並べる。「同じ fixture / 同じ ruleset / 同じバージョン」で並列実行する fairness を保つ。

「secscan が単体ツールに勝つ」は目的ではない (むしろ multi-tool aggregate なので**同等性**が期待結果)。比較表のメッセージは「**secscan は単体ツールを silent に下回っていない**」(=信頼できる integrator) という形にする。

## runner の I/O

```
$ python bench/run.py --output bench/report.md
secscan benchmark v0.6.0
========================
deps:
  npm-vulnerable: 2/2 detected (100.0%)
  pnpm-vulnerable: 2/2 detected (100.0%)
  yarn-vulnerable: ...
  ...
secrets:
  synthetic: 4/4 patterns detected; 0 false positives on clean/
sast/python: 3/4 CWEs detected (75.0%); missing: CWE-502
dast: SKIPPED (--dast required)

Wrote bench/report.md and bench/report.json
```

`--dast` フラグを付けた時だけ DAST 走行 (docker-compose up → scan → docker-compose down)。

## CI 連携

- 通常の `pytest` 実行とは独立 (heavy)
- 別ジョブ `make bench` で走らせる
- 結果の `bench/report.md` を commit するかは PR 単位の判断 (CI 自動 commit はしない)
- gitleaks / pip-audit / semgrep がない CI 環境では scanner 単位で SKIPPED 扱い

## セキュリティ考慮

- **fixture 内の "secret" は全て無効**: AWS の AKIA…EXAMPLE 等、公式に "example" としてリストされた値のみ使用。プロダクション値を間違って commit しない
- **vulnerable な依存性は install しない**: package-lock.json / requirements.txt は present でも `npm install` / `pip install` はしない。secscan は manifest のみ読むので install 不要
- **bench runner 自身も secscan scan を subprocess で呼ぶ**: shell=False, argv list で既存 SubprocessCommandRunner と同じ姿勢
- **`bench/` は default の scan target から除外推奨**: `.secscan.toml` の skip / .gitignore 的なエスケープ。bench fixture が secscan secrets 自体に検知されると、本物の secret と区別がつかなくなる

## GLM 5.1 1 次レビュー反映済み

### 1. retract 耐性 (fixture 再現性)

- `expected.json` に **`advisory_db_snapshot`** フィールドを追加: 「このベンチが GHSA を verify した時点の advisory DB の状態」を ISO 日付で記録
- `bench/run.py` は実行時に GHSA → ghsa.dev (or osv.dev) を crawl せず、**advisory DB は scanner が見るままを信頼**する (オフライン bench)
- ただし、検知ゼロの場合は `retracted_or_renamed?` warning を出力:
  - "expected GHSA-X but secscan + reference tool both returned 0 — has the advisory been retracted? See bench/README.md#retraction-policy"
- README の retraction policy:
  - retract 確認後、対象 fixture を **削除せず別の stable advisory に差し替える** (commit log で履歴を残す)
  - 大量 retract 発生時は bench-version を bump (報告 recall は always 同 bench-version 内でしか比較できない)

### 2. precision 感度確保 (誤検出測定)

`clean/` には 2 系統のファイルを置く:

- **`obvious_clean/`**: 完全に無害なコード — 最低限の sanity check
- **`borderline_clean/`** (GLM 指摘反映): 脆弱パターンに**形状は似ているが安全**なコード。たとえば:
  - `cwe78_safe_subprocess.py`: `subprocess.run([cmd], shell=False)` (引数 list で正規)
  - `cwe89_safe_sql.py`: cursor.execute("SELECT * FROM t WHERE id=?", (id,)) (parameter binding)
  - `cwe502_safe_yaml.py`: yaml.safe_load(...) を明示
  - `aws_lookalike.txt`: 「AKIA」で始まるが entropy が低くて gitleaks の閾値以下、または ↑ プレフィックスが意図的にダミー

これらで FP が出るかを観測。FP=0% の場合は「scanner は境界ケースを正しく拒否している」と書ける。

### 3. 業界比較の fairness 表記 (GLM 指摘反映)

比較表に **「≥ Best Single Tool」** 列を追加:

| Fixture | npm-audit | secscan deps | ≥ Best | Note |
|---|---|---|---|---|
| npm-vulnerable | 2 | 2 | ✅ (=) | 同等 (integration overhead は許容内) |
| pip-vulnerable | 3 | 3 | ✅ (=) | 同等 |

「secscan は単体ツールに勝つ」ことではなく「**統合のオーバーヘッドが recall を毀損していない**」ことが報告メッセージ。`≥` 達成率 = 「secscan 検知数 / 最良単体ツール検知数 ≥ 1.0 となった fixture の割合」を全体サマリーに出す。

## Codex 2 次レビュー反映 (実装制約として組み込み)

### 1. argv / path 安全性

- `bench/run.py` は **`SAFE_FIXTURE_ROOT = Path("bench/fixtures").resolve()`** を定数化
- 各 fixture path は `SAFE_FIXTURE_ROOT.resolve()` を取得 → `is_relative_to(SAFE_FIXTURE_ROOT)` を assert
- それ以外の path が argv に乗ることはランナーが拒否
- secscan を呼ぶ argv: `["secscan", "<subcommand>", "--path", "--", str(fixture_path)]`
  ... ではなく、argparse の標準 `--path <path>` で渡し、`--path` 自身が positional でなく option なので `--` セパレータは不要 (secscan の cli.py を再確認)
- ただし fixture path が `-` で始まる場合は ValueError で拒否 (defense in depth)
- 比較ツール (npm/pip-audit/gitleaks/semgrep) も同様の argv 制約

### 2. synthetic secret の改変防止

`bench/fixtures/secrets/synthetic/_manifest.json` (新規) に各ファイルの SHA-256 hash + 無効性証跡を記録:

```json
{
  "fixtures": [
    {
      "file": "aws_invalid.txt",
      "sha256": "abc...",
      "source": "AWS documentation example credentials",
      "source_url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/...",
      "invalidity_reason": "AKIAIOSFODNN7EXAMPLE is the official example key used in AWS docs; never valid",
      "added_at": "2026-05-24"
    }
  ]
}
```

`bench/run.py` は各 secrets fixture の SHA-256 を計算し、manifest と一致しなければ **DO NOT TRUST: hash mismatch — refusing to run** で停止。CI でも同じチェックを走らせる (`make bench-verify`).

### 3. 比較ツール cwd 隔離

`bench/compare.py` は各比較ツール実行前に以下を行う:

1. `tmp_root = tempfile.mkdtemp(prefix="secscan-bench-")` (0700 permission)
2. fixture を `shutil.copytree(fixture_src, tmp_root / "fixture", ignore_dangling_symlinks=True)`
3. 比較ツールの `cwd=tmp_root / "fixture"` で `env={"HOME": tmp_root, "XDG_CACHE_HOME": tmp_root, "NPM_CONFIG_CACHE": tmp_root, "PIP_CACHE_DIR": tmp_root, "PATH": os.environ["PATH"]}` で起動
4. 実行後、`source_dir` と `tmp_root/fixture` の hash 比較 → 差分があれば fixture 純潔性違反として fail (実行中の書き込みを検知)
5. finally で `shutil.rmtree(tmp_root)`

これで:
- 比較ツールが cache を fixture 内に書く事故を防止
- repo 内 fixture が実行で汚染されないことを CI で検証
- HOME 経由でユーザの `.npmrc` 等が leak しないことを保証

### Codex 指摘 (要約)

| # | 指摘 | 反映先 |
|---|---|---|
| 1.1 | fixture path 配下制約 | run.py の SAFE_FIXTURE_ROOT |
| 1.2 | `--` 区切り | argv は `--path` option で渡す + 先頭 `-` 拒否 |
| 2.1 | 値改変防止 | _manifest.json with SHA-256 |
| 2.2 | 無効性証跡 | manifest に source/url/reason/added_at |
| 3.1 | cwd 隔離 | tmpdir copy で実行 |
| 3.2 | cache/env 書込制御 | env を tmpdir に固定 + 差分検証 |

## Kimi / GLM reconfirm 観点

Codex の 6 指摘 (path/argv ×2, secret manifest ×2, cwd 隔離 ×2) がすべて設計に反映されているかを機械的に確認すれば OK。新規観点は不要。

## 元 期待観点 (履歴)

最初の 1 次/2 次レビューで尋ねた観点 (反映済みのため archive):
- fixture の再現性 (advisory retract) → snapshot 日付 + retract warning で対応
- 誤検出測定の妥当性 → borderline_clean/ で境界ケース測定
- 業界比較の fairness → 「≥ Best Single Tool」列で integration overhead を可視化
- argv / path 安全性 → SAFE_FIXTURE_ROOT
- synthetic secret 無害性 → SHA-256 manifest
- 比較ツール cwd → tmpdir コピー

## 期待形式

- Markdown 表で観点 → 指摘 → 推奨
- 各指摘 80 字以内、箇条書きのみ
- 既存 invariants は前提として再評価不要
- 推測は「不明」と明記

既存 secscan invariants は前提として再評価不要。以下のみ:

1. **bench/run.py が secscan を subprocess で呼ぶ際の path / argv 安全性**: ベンチランナーは secscan 本体の SubprocessCommandRunner と同じ姿勢か? `fixture path` がランナー argv に乗る際の path-traversal / flag-injection リスク
2. **fixture 内 "synthetic secret" の真の無害性**: AWS の AKIA...EXAMPLE 等を repo に置く際、誤って valid な credential format に到達する余地 (誰かが diff で値を変えて push してしまう orgr) を実装でどう防ぐか
3. **比較ツール (npm-audit / pip-audit / gitleaks / semgrep) を bench/compare.py が呼ぶ際の cwd 制御**: fixture ディレクトリで `npm audit` を実行すると `package-lock.json` がそこで作られる / advisory cache がそこに書き込まれる可能性。fixture 純潔性を壊さない設計か

## 期待形式

- Markdown 表で観点 → 指摘 → 推奨
- 各指摘 80 字以内、箇条書きのみ
- 既存 invariants は前提として再評価不要
- 推測は「不明」と明記
