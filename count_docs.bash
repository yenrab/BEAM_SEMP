#!/usr/bin/env bash
set -euo pipefail

grand_doc=0
grand_nonempty=0

# Only pick up *.erl files
while IFS= read -r -d '' file; do
  read doc_count nonempty_count < <(
    awk -f - "$file" <<'AWK'
BEGIN { inblk=0; doc_total=0; nonempty_total=0 }

# Count all non-empty lines
$0 ~ /[^[:space:]]/ { nonempty_total++ }

# Start a block: line begins with optional spaces then "-doc" + space
$0 ~ /^[[:space:]]*-doc[[:space:]]/ {
  inblk=1
  doc_total++                  # count the -doc line
  next
}

# While in a block, count every line; end only when line ends with '".'
inblk {
  doc_total++
  if ($0 ~ /"\.[[:space:]]*$/)   # end marker
    inblk=0
  next
}

END { print doc_total, nonempty_total }
AWK
  )

  grand_doc=$((grand_doc + doc_count))
  grand_nonempty=$((grand_nonempty + nonempty_count))
done < <(find . -type f -name '*.erl' -print0)

printf "TOTAL: doc_lines=%d nonempty_lines=%d\n" "$grand_doc" "$grand_nonempty"
