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
