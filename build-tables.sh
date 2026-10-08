#!/usr/bin/env bash
# ---------------------------------------------------------------------------
#  build-tables.sh -- generate a "sufficiently large" set of rainbow tables.
#
#  This is the preprocessing step. It calls ./gen-table several times and
#  stores the resulting tables in a directory (default: ./tables).
#
#  Usage:
#       ./build-tables.sh [PROFILE] [output_dir]
#       ./build-tables.sh --bench            # just measure your SHA-256 speed
#
#  PROFILE (default: fast):
#     --light  4xL6 + 2xL7              -> ~1 night even on a modest laptop (~1.7e12 hashes)
#     --fast   4xL6 + 4xL7              -> best crack rate, ~1 night on a SHA-NI laptop (~3.1e12 hashes)
#     --full   --fast + 1xL8            -> adds a (mostly symbolic) length-8 pass
#     --max    --fast + L8 + L9 + L10   -> attempts the whole 6..10 range
#
#  --fast is the recommended profile. If --bench says your machine is slow
#  (scalar SHA-256, few cores), use --light, or lower NTAB[7] below.
#
#  IMPORTANT, read this before choosing:
#     The key space is 62^L. Length 6 is fully coverable, length 7 partly, and
#     lengths 8/9/10 are astronomically large (62^8 = 2.2e14 ... 62^10 = 8.4e17)
#     so on a single laptop in one night they crack almost nothing. Spending the
#     night on them STEALS time from 6/7 where cracks actually happen. On a test
#     set with uniform lengths 6..10, the theoretical maximum any laptop can
#     reach is ~40% (all of L6 + L7). 50% is only possible if the hashes are
#     skewed toward short passwords -- in which case --fast is exactly right.
#
#  Per table: cost ~ M*T SHA-256 evaluations, size ~ M*16 bytes.
#  Run ./build-tables.sh --bench first to size the tables to YOUR machine.
# ---------------------------------------------------------------------------
set -euo pipefail

GEN=./gen-table
[ -x "$GEN" ] || { echo "gen-table not found -- run ./build.sh first"; exit 1; }

# ---- quick benchmark -------------------------------------------------------
if [ "${1:-}" = "--bench" ]; then
    echo ">> Benchmarking SHA-256 throughput (1 billion hashes)..."
    t0=$(date +%s.%N)
    "$GEN" 6 1000000 1000 99 /tmp/rt_bench.rtbl >/dev/null 2>/tmp/rt_bench.log
    t1=$(date +%s.%N)
    grep -m1 "SHA-256" /tmp/rt_bench.log || true
    rate=$(awk "BEGIN{printf \"%.0f\", 1e9/($t1-$t0)}")
    secs=$(awk "BEGIN{printf \"%.1f\", $t1-$t0}")
    echo ">> 1e9 hashes in ${secs}s  ->  ~${rate} hashes/s"
    awk -v r="$rate" 'BEGIN{
        printf ">> One-night budget (10h): ~%.2e hashes\n", r*36000;
        printf ">> Rough guide: full L6 needs ~2.3e11, one L7 table ~3.5e12\n";
    }'
    rm -f /tmp/rt_bench.rtbl
    exit 0
fi

# ---- profile selection -----------------------------------------------------
PROFILE="fast"
case "${1:-}" in
    --light|--fast|--full|--max) PROFILE="${1#--}"; shift ;;
    --*) echo "unknown profile: $1"; exit 1 ;;
esac
OUT="${1:-tables}"
mkdir -p "$OUT"

# Per length: number of chains (M), chain length (T), number of tables (NTAB).
# Tuned to fit roughly one night with hardware-accelerated SHA-256 while
# staying under 20 GB on disk and 6 GB in RAM.
declare -A M T NTAB
M[6]=6000000    ; T[6]=10000 ; NTAB[6]=4
M[7]=60000000   ; T[7]=12000 ; NTAB[7]=4
M[8]=150000000  ; T[8]=15000 ; NTAB[8]=0
M[9]=200000000  ; T[9]=20000 ; NTAB[9]=0
M[10]=200000000 ; T[10]=20000; NTAB[10]=0

case "$PROFILE" in
    light) NTAB[7]=2 ;;                        # 4xL6 + 2xL7 (lighter, for slow machines)
    fast)  ;;                                  # 4xL6 + 4xL7 (defaults above, recommended)
    full)  NTAB[8]=1 ;;                        # + one length-8 table
    max)   NTAB[8]=1; NTAB[9]=1; NTAB[10]=1 ;; # attempt the whole range
esac

LENGTHS=(6 7 8 9 10)

echo "Profile: --$PROFILE     Output: $OUT"
echo "(tip: run './build-tables.sh --bench' to size these to your machine)"
echo

for L in "${LENGTHS[@]}"; do
    n="${NTAB[$L]:-0}"
    for ((id=0; id<n; id++)); do
        f="$OUT/t${L}_${id}.rtbl"
        rm -f "$f.tmp"                      # drop any leftover partial write
        if [ -s "$f" ]; then
            echo ">> length $L, table $id already done ($f) -- skipping"
            continue                        # RESUME: re-running continues where it stopped
        fi
        echo "=============================================================="
        echo " length $L, table $id  ->  $f"
        echo "=============================================================="
        "$GEN" "$L" "${M[$L]}" "${T[$L]}" "$id" "$f"
    done
done

echo
echo "All requested tables built in: $OUT"
du -sh "$OUT" 2>/dev/null || true
echo "Attack with:   ./attack hashes.txt cracked.txt $OUT/*.rtbl"
