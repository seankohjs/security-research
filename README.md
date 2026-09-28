# Koh Jun Sheng — Security research

A small, static index of my public vulnerability disclosures from SMU's TITAN project.

**Website:** https://seankohjs.github.io/security-research/

Each entry links to the maintainer's published GitHub Security Advisory and, where listed, its CVE record. The page includes only publicly published advisories; the displayed totals describe this public list, not all accepted findings.

## Update the page

1. Confirm that the maintainer's advisory is public and not withdrawn.
2. Add or update its metadata in `advisories.json`. Use `null` for a CVE ID that is not publicly listed. Dates use `YYYY-MM-DD`.
3. Update `last_verified` and run `python3 scripts/build.py`.
4. Commit the JSON and generated `index.html`, then push to `main`.

The generator uses only Python's standard library and makes no network requests. The published site is plain HTML and CSS; it needs no JavaScript, cookies, analytics, build service, or third-party fonts.

GitHub Pages serves the root of the `main` branch. `.nojekyll` disables Jekyll processing.

Advisory titles, severity, dates, and identifiers come from the linked public maintainer advisories. The maintainer pages are the source of record for fixes and technical details.
