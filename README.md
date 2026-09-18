# Clickjacking Detection Tool - Week 4 (HR Lab Context)

## Objective
A defensive scanner that checks authorized lab targets for missing or weak
clickjacking protections, and produces a reusable, automated report
(JSON + CSV) instead of manual, one-off testing.

## How It Works
1. Reads a list of authorized target URLs from `urls.txt`.
2. Sends a GET request to each URL.
3. Inspects the response headers for:
   - `X-Frame-Options` (DENY / SAMEORIGIN expected)
   - `Content-Security-Policy: frame-ancestors` directive
4. Classifies the target as **Vulnerable** or **Safe** based on:
   - No header/directive at all → **High** severity (fully vulnerable)
   - Weak/non-standard `X-Frame-Options` value → **Medium** severity
   - Wildcarded `frame-ancestors *` → **High** severity
   - Proper DENY/SAMEORIGIN or restricted frame-ancestors → **Safe**
5. Writes evidence + a remediation suggestion for every result.
6. Saves everything to `clickjacking_report.json` and `.csv`.

## Usage
```bash
pip install requests
python clickjack_detector.py urls.txt
```

## Testing True/False Positives
- **True positive check:** ran against a target with no `X-Frame-Options`/CSP
  set → correctly flagged as Vulnerable (High).
- **False positive check:** ran against a target with `X-Frame-Options: DENY`
  set → correctly flagged as Safe.
- (Fill in your actual test results/screenshots here once you run it against
  your lab target, e.g. the Flask app shown in your demo.)

## Known Limitations
- Only checks HTTP response headers - does not attempt an actual iframe
  embed/exploit (by design, this is a detection-only tool).
- Does not evaluate `X-Frame-Options: ALLOW-FROM` origin correctness beyond
  presence (this header is deprecated in modern browsers anyway).
- Does not follow JavaScript-based frame-busting scripts - header-based
  detection only, which is the current best-practice defense.
- Single-threaded - fine for a handful of lab URLs, not built for large-scale
  scanning.

## Deliverables Mapping (Quality Checklist)
- [x] Only authorized lab environments tested — `urls.txt` restricted to lab targets
- [x] Detection logic tested for true/false positives — see section above
- [x] Report includes evidence, severity, remediation — see `clickjacking_report.csv`/`.json`
- [x] Tool reusable against a new list of authorized URLs — just edit `urls.txt`
- [x] Limitations clearly documented — see above
- [ ] Code and report pushed to GitHub — do this last, see steps below

## Steps to Finish & Submit (fast path)
1. Edit `urls.txt` with your actual authorized lab target(s).
2. Run the tool: `python clickjack_detector.py urls.txt`
3. Open `clickjacking_report.csv` — screenshot it or paste the table into your report doc.
4. Copy this README's "Known Limitations" + "Deliverables Mapping" sections into your submission doc.
5. `git init`, commit `clickjack_detector.py`, `urls.txt`, `README.md`, and the generated report files, then `git push` to your GitHub repo.
6. Tick off the checklist items in your submission.
