# pn-vuln-data

ミツクル（株式会社PULL-NET）の WEBセキュリティ診断で使う、WordPress 本体・プラグイン・テーマの
既知の脆弱性の索引です。GitHub Actions が毎日1回作り直し、`data` ブランチに置きます。

- 索引：`data` ブランチの `b/00.json.gz`〜`b/31.json.gz`（キーで32に分けた gzip の JSON）
- 作成日時・出典・件数・ファイルごとのハッシュ：`data` ブランチの `index.meta.json`
- 分け方：`md5(キー)` の先頭4けた（16進）を 32 で割った余り（2けた）。キーは `plugin:<slug>` など
- 作り方：`build_index.py`（入力は Wordfence Intelligence の Vulnerability Data Feed v3 production）

## 出典

脆弱性情報の出典は Wordfence Intelligence（Defiant, Inc.）です。
利用条件：https://www.wordfence.com/wordfence-intelligence-terms-and-conditions/

CVE の情報は The MITRE Corporation の著作物を含みます。
利用条件：https://www.cve.org/Legal/TermsOfUse

## 分けたファイル1つの形（version 1）

```json
{
  "version": 1,
  "bucket": "07",
  "items": {
    "plugin:<slug>": [["from", 1, "to", 1, "high", "CVE-xxxx-xxxx", "タイトル", "修正版", "wordfence-id"]],
    "theme:<slug>": [],
    "core:wordpress": []
  }
}
```

各行は `[from, from_inclusive, to, to_inclusive, severity, cve, title, patched_versions, id]`。`patched_versions` は修正版をカンマでつないだもの（系統ごとに出る）。
`from` / `to` の `*` は「下限なし／上限なし」。バージョンの比較は使う側で行います。

## 手で動かす

```bash
WORDFENCE_API_KEY=xxxx python build_index.py "" out
# 手元のフィードのファイルから作る場合
python build_index.py feed.json out
```
