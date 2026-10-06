# Public corpus evaluation

On 2026-08-09, version 0.1.0 scanned four public Hugging Face dataset
repositories at their resolved commits: `glue` (`bcdcba7`), `squad`
(`7b6d24c`), `imdb` (`e628166`), and `wikitext` (`b08601e`). Each scan used
`--max-files 30 --max-file-size 1000000` and reported zero findings.

Every scan was incomplete because the repositories contain data shards and
metadata entries outside those bounds. This is a smoke evaluation of tool
behaviour, not a precision/recall measurement: these repositories have no
independent ground-truth labels for the scanner's rules. Issue #25 remains
open until a labelled benign/malicious corpus and manual finding review are
available.

## Reproducible labelled evaluation

Use a reviewed manifest with immutable revisions and ground-truth labels, then
run:

```bash
python tools/evaluate_corpus.py docs/corpus-manifest.example.json evaluation-output
```

The script writes one JSON report per manifest entry plus `summary.json`.
Reports have an ordinal prefix (for example, `0001_owner__dataset.json`) so
multiple revisions of one repository retain separate reports. Each summary
entry includes its requested revision and report filename; reviewers can
compare labels with findings and record false positives/negatives.

When rerunning into the same output directory, each current entry's old report
is removed before scanning. A failed scan does not reuse earlier results.
The script continues through the corpus and exits with code 1 if any scan
failed, preserving each scan's exit code in the summary. A completed scan can
still be incomplete; review `scan_complete` separately. Reports left by entries
removed from the manifest are not part of the current summary.

Do not use the example manifest as data—it contains placeholders only.
