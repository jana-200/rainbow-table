#!/usr/bin/env bash
# ---------------------------------------------------------------------------
#  build-tables.sh -- generate a "sufficiently large" set of rainbow tables.
#
#  This is the preprocessing step. It calls ./gen-table several times and
#  stores the resulting tables in a directory (default: ./tables).
#
#  Usage:
#       ./build-tables.sh [output_dir]
#
#  The defaults below are sized to run in roughly one night on a typical
#  multi-core laptop and to stay well under the 20 GB disk / 6 GB RAM limits.
#  They put most of the effort on the shorter password lengths, which is where
#  the key space is small enough to be covered well (62^6 is tractable, 62^10
#  is astronomically large). Edit the arrays below to spend more/less time or
#  cover more lengths.
#
#  For each length L we build NTAB[L] independent tables (distinct table ids);
#  more tables of the same length => higher success rate at proportional cost.
#  Per table the cost is ~ M[L] * T[L] SHA-256 evaluations and M[L]*16 bytes.
# ---------------------------------------------------------------------------
set -euo pipefail

OUT="${1:-tables}"
mkdir -p "$OUT"

GEN=./gen-table
[ -x "$GEN" ] || { echo "gen-table not found -- run ./build.sh first"; exit 1; }

# Lengths to cover and, per length: number of chains (M), chain length (T),
# and how many independent tables to build (NTAB).
#
#            L:      6          7          8
declare -A M=(  [6]=6000000  [7]=70000000 [8]=120000000 )
declare -A T=(  [6]=10000    [7]=10000    [8]=12000     )
declare -A NTAB=( [6]=4      [7]=2        [8]=0         )   # set [8] >0 to also attempt length 8

LENGTHS=(6 7 8)

echo "Output directory: $OUT"
for L in "${LENGTHS[@]}"; do
    n="${NTAB[$L]:-0}"
    for ((id=0; id<n; id++)); do
        f="$OUT/t${L}_${id}.rtbl"
        echo "=============================================================="
        echo " length $L, table $id  ->  $f"
        echo "=============================================================="
        "$GEN" "$L" "${M[$L]}" "${T[$L]}" "$id" "$f"
    done
done

echo
echo "All requested tables built in: $OUT"
du -sh "$OUT"
echo "Attack with:   ./attack hashes.txt cracked.txt $OUT/*.rtbl"
