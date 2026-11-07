#!/usr/bin/env python3
"""Wordfence Intelligence の脆弱性フィード（v3 production）を、ミツクルの診断で使う小さな索引に縮める。

- 入力：フィードの JSON（ファイルのパス、または環境変数 WORDFENCE_API_KEY があれば API から取得）
- 出力：b/00.json.gz〜b/31.json.gz（キーで32に分けた索引）と index.meta.json
  （作成日時・出典・件数・分けたファイルごとのハッシュ）

分けたファイル1つの形（version 1）:
{
  "version": 1,
  "bucket": "07",
  "items": {
    "plugin:contact-form-7": [
      # [from, from_inc, to, to_inc, severity, cve, title, patched_in, wf_id]
      ["*", 1, "5.3.1", 1, "high", "CVE-2020-35489", "...", "5.3.2", "abcd..."]
    ],
    "theme:twentytwenty": [...],
    "core:wordpress": [...]
  }
}

方針：
- informational（脆弱性ではない情報）の記録は入れない。
- バージョンの比較はミツクル側（PHP の version_compare）で行う。ここでは範囲をそのまま写すだけ。
- 入力が壊れていたら索引を作らずに失敗で終わる（古い索引をそのまま残すため）。
"""

import gzip
import hashlib
import json
import os
import sys
import urllib.request
from datetime import datetime, timezone

FEED_URL = "https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production"
TYPES = {"plugin", "theme", "core"}
SEVERITIES = {"none", "low", "medium", "high", "critical"}
# フィードが小さすぎるときは壊れているとみなす（実際の件数は数万件）。
MIN_RECORDS = int(os.environ.get("PNV_MIN_RECORDS", "1000"))
# 索引を分ける数（使う側 PNM_Vuln_Index::BUCKETS と同じ）。
BUCKETS = 32


def load_feed(path):
    if path:
        with open(path, "rb") as f:
            raw = f.read()
    else:
        key = os.environ.get("WORDFENCE_API_KEY", "")
        if not key:
            sys.exit("WORDFENCE_API_KEY が無く、入力ファイルの指定もありません")
        req = urllib.request.Request(
            FEED_URL,
            headers={"Authorization": "Bearer " + key, "User-Agent": "pn-vuln-data/1.0"},
        )
        with urllib.request.urlopen(req, timeout=300) as r:
            raw = r.read()
    data = json.loads(raw)
    if not isinstance(data, dict):
        sys.exit("フィードの形が想定と違います（dict ではない）")
    return data


def s(v, limit=200):
    if v is None:
        return ""
    v = str(v).strip()
    return v[:limit]


def build(feed):
    items = {}
    skipped = 0
    for wf_id, rec in feed.items():
        if not isinstance(rec, dict) or rec.get("informational"):
            skipped += 1
            continue
        cvss = rec.get("cvss") or {}
        sev = s(cvss.get("rating"), 20).lower()
        if sev not in SEVERITIES:
            sev = ""
        cve = s(rec.get("cve"), 40)
        title = s(rec.get("title"), 200)
        for sw in rec.get("software") or []:
            if not isinstance(sw, dict):
                continue
            typ = s(sw.get("type"), 20).lower()
            slug = s(sw.get("slug"), 120).lower()
            if typ not in TYPES or not slug:
                continue
            if typ == "core":
                slug = "wordpress"
            patched = sw.get("patched_versions") or []
            patched_in = s(patched[0], 40) if patched else ""
            for rng in (sw.get("affected_versions") or {}).values():
                if not isinstance(rng, dict):
                    continue
                items.setdefault(typ + ":" + slug, []).append([
                    s(rng.get("from_version"), 40) or "*",
                    1 if rng.get("from_inclusive") else 0,
                    s(rng.get("to_version"), 40) or "*",
                    1 if rng.get("to_inclusive") else 0,
                    sev,
                    cve,
                    title,
                    patched_in,
                    s(wf_id, 64),
                ])
    for k in items:
        items[k].sort(key=lambda r: (r[2], r[8]))
    return items, skipped


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else ""
    out_dir = sys.argv[2] if len(sys.argv) > 2 else "."
    feed = load_feed(src)
    if len(feed) < MIN_RECORDS:
        sys.exit("フィードの件数が少なすぎます（%d 件）。索引を作りません" % len(feed))
    items, skipped = build(feed)
    if not items:
        sys.exit("索引が空になりました。索引を作りません")

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    # 使う側（Xserver の PHP）が一度に読む量を小さくするため、キーで BUCKETS 個に分ける。
    # 🔴 分け方は使う側と同じ式：md5(キー) の先頭4けた（16進）を BUCKETS で割った余り（2けた）。
    shards = {}
    for k, rows in items.items():
        b = "%02d" % (int(hashlib.md5(k.encode("utf-8")).hexdigest()[:4], 16) % BUCKETS)
        shards.setdefault(b, {})[k] = rows
    os.makedirs(os.path.join(out_dir, "b"), exist_ok=True)
    buckets = {}
    for i in range(BUCKETS):
        b = "%02d" % i
        body = json.dumps({"version": 1, "bucket": b, "items": shards.get(b, {})},
                          ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        gz = gzip.compress(body, compresslevel=9, mtime=0)
        with open(os.path.join(out_dir, "b", b + ".json.gz"), "wb") as f:
            f.write(gz)
        buckets[b] = {"sha256": hashlib.sha256(gz).hexdigest(), "bytes": len(gz)}
    meta = {
        "version": 1,
        "generated_at": generated_at,
        "buckets_count": BUCKETS,
        "attribution": {
            "source": "Wordfence Intelligence (Defiant, Inc.)",
            "source_url": "https://www.wordfence.com/threat-intel/vulnerabilities/",
            "license_url": "https://www.wordfence.com/wordfence-intelligence-terms-and-conditions/",
            "cve_notice": "CVE: Copyright The MITRE Corporation",
            "cve_terms_url": "https://www.cve.org/Legal/TermsOfUse",
        },
        "records_in_feed": len(feed),
        "records_skipped": skipped,
        "software": len(items),
        "ranges": sum(len(v) for v in items.values()),
        "buckets": buckets,
    }
    with open(os.path.join(out_dir, "index.meta.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)
    print(json.dumps({k: v for k, v in meta.items() if k != "buckets"}, ensure_ascii=False))


if __name__ == "__main__":
    main()
