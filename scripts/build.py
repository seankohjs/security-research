#!/usr/bin/env python3
"""Render the public advisory index. Standard library only; no network calls."""

from datetime import date
from html import escape
import json
from pathlib import Path
import re
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
data = json.loads((ROOT / "advisories.json").read_text())
advisories = sorted(data["advisories"], key=lambda item: item["published"], reverse=True)
seen = set()
rows = []
for item in advisories:
    ghsa, cve = item["ghsa"], item["cve"]
    assert re.fullmatch(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", ghsa)
    assert ghsa not in seen, f"Duplicate advisory: {ghsa}"
    seen.add(ghsa)
    assert not cve or re.fullmatch(r"CVE-\d{4}-\d{4,}", cve)
    assert item["severity"] in {"low", "medium", "high", "critical"}
    assert re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", item["project"])
    expected_url = f'https://github.com/{item["project"]}/security/advisories/{ghsa}'
    assert item["advisory_url"] == expected_url
    assert urlparse(item["advisory_url"]).scheme == "https"
    published = date.fromisoformat(item["published"])
    cve_link = (
        f'<a href="https://www.cve.org/CVERecord?id={cve}">{cve}</a>'
        if cve else '<span class="no-cve">GHSA only</span>'
    )
    rows.append(f'''          <tr id="{ghsa}">
            <th scope="row">
              <a class="project" href="https://github.com/{escape(item['project'])}">{escape(item['project'])}</a>
              <p class="finding">{escape(item['title'])}</p>
            </th>
            <td class="identifiers">
              {cve_link}
              <a href="{escape(item['advisory_url'])}">{ghsa}</a>
            </td>
            <td class="classification"><span class="severity {item['severity']}">{item['severity'].title()}</span></td>
            <td class="date"><time datetime="{published.isoformat()}">{published.strftime('%d %b %Y')}</time></td>
          </tr>''')

count = len(advisories)
cve_count = len({item["cve"] for item in advisories if item["cve"]})
verified = date.fromisoformat(data["last_verified"])
html = f'''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="Koh Jun Sheng's public security research: maintainer-published vulnerability disclosures, CVE IDs, and GitHub Security Advisories from the SMU TITAN project.">
  <meta name="color-scheme" content="light">
  <title>Security research — Koh Jun Sheng</title>
  <link rel="stylesheet" href="styles.css">
</head>
<body>
  <a class="skip-link" href="#advisories">Skip to advisories</a>
  <div class="page">
    <header class="masthead">
      <span class="name">Koh Jun Sheng</span>
      <a href="https://github.com/seankohjs">GitHub / seankohjs</a>
    </header>
    <main>
      <section class="intro" aria-labelledby="page-title">
        <p class="eyebrow">Selected work · May–August 2026</p>
        <h1 id="page-title">Security research</h1>
        <p class="description">Public vulnerability disclosures from my work on SMU’s <a href="https://titancaproject.github.io/">TITAN project</a>, combining AI-assisted research with human validation and reproducible proofs of concept.</p>
        <p class="stats"><strong>{count}</strong> public advisories <span aria-hidden="true">/</span> <strong>{cve_count}</strong> linked CVE IDs</p>
      </section>
      <section id="advisories" aria-labelledby="advisory-heading" tabindex="-1">
        <div class="section-heading">
          <h2 id="advisory-heading">Published disclosures</h2>
          <span>Newest first</span>
        </div>
        <table>
          <caption class="sr-only">Public vulnerability disclosures with project, finding, advisory identifiers, severity, and publication date.</caption>
          <thead>
            <tr><th scope="col">Project / finding</th><th scope="col">Advisory links</th><th scope="col">Severity</th><th scope="col">Published</th></tr>
          </thead>
          <tbody>
{chr(10).join(rows)}
          </tbody>
        </table>
      </section>
    </main>
    <footer>
      <p>Titles, severity, and identifiers are sourced from the linked maintainer advisories.</p>
      <p>Verified <time datetime="{verified.isoformat()}">{verified.strftime('%d %B %Y')}</time> · <a href="https://github.com/seankohjs/security-research">Page source</a></p>
    </footer>
  </div>
</body>
</html>
'''
(ROOT / "index.html").write_text(html)
print(f"Built index.html: {count} published advisories, {cve_count} CVE IDs.")
