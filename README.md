# SSD & WS — Rainbow attack

Group homework: implement a rainbow-table attack against SHA-256 hashes of
alphanumeric passwords (length 6 to 10, unsalted, single hash pass).

## Group members

<!-- Fill in before submitting -->

| Name | Matricule |
|------|-----------|
| _TODO_ | _TODO_ |
| _TODO_ | _TODO_ |
| _TODO_ | _TODO_ |

## What is delivered

Two main programs, as required by the statement:

* **`gen-table`** — *preprocessing script*: builds a rainbow table (one table
  per password length) and writes it to disk.
* **`attack`** — *attack script*: reads a file of SHA-256 hashes and writes the
  cracked passwords, using one or more rainbow tables.

Plus helper scripts:

* **`build.sh`** — installs missing dependencies and compiles everything.
* **`build-tables.sh`** — runs `gen-table` several times to produce a
  "sufficiently large" set of tables (this is the overnight preprocessing).
* The teacher-provided **`gen-passwd`** and **`check-passwd`** are also built,
  for testing.

The rainbow tables themselves are **not** committed (they are large and the
statement forbids submitting them); they are regenerated with `build-tables.sh`.

## How to build (Ubuntu 24.04)

From the repository root:

```bash
./build.sh
```

This installs `build-essential` (g++ + make) if missing and compiles the four
binaries: `gen-table`, `attack`, `gen-passwd`, `check-passwd`.

Equivalently, if g++ (C++17) is already installed:

```bash
make
```

On **Windows 11**, install [MSYS2](https://www.msys2.org/) or WSL (Ubuntu),
then run `make` from the g++ shell — the code only uses the standard library,
`std::thread`, and the GCC/Clang `__uint128_t` extension.

## How to use

### 1. Preprocessing — build the rainbow tables (do this once)

```bash
./build-tables.sh tables
```

This writes `tables/t<L>_<id>.rtbl`. With the default parameters it targets
roughly one night on a multi-core laptop and stays well under the 20 GB disk /
6 GB RAM limits. Edit the `M`, `T`, `NTAB` arrays at the top of
`build-tables.sh` to spend more or less effort (see **Tuning** below).

You can also build a single table by hand:

```bash
# gen-table  L  m        t      table_id  out_file  [threads]
./gen-table  6  6000000  10000  0         tables/t6_0.rtbl
```

### 2. Attack — crack a file of hashes

```bash
# attack  in_hashes  out_passwords  table1 [table2 ...]  [--threads n]
./attack  hashes.txt  cracked.txt  tables/*.rtbl
```

* **Input** (`hashes.txt`): one lowercase-hex SHA-256 per line, last line blank
  — exactly the format produced by the provided `gen-passwd`.
* **Output** (`cracked.txt`): one password per line, in the same order as the
  input; a hash that could not be cracked becomes a line containing only `?`.
  The file ends with a blank line.

### Quick end-to-end test

```bash
./gen-passwd 200 6 6 pw.txt h.txt          # 200 length-6 passwords + hashes
./gen-table  6 6000000 10000 0 t6.rtbl     # one length-6 table
./attack     h.txt cracked.txt t6.rtbl     # crack them
paste pw.txt cracked.txt                    # compare (ignoring '?')
```

## How it works

* **Indexing.** A password of length `L` is a number in `[0, 62^L)` via base-62
  encoding over the 62-character alphanumeric alphabet (the same one as
  `gen-passwd`). `62^10 < 2^63`, so a single `uint64_t` indexes any password.
* **Chains.** A chain is `start → H,R₀ → p₁ → H,R₁ → … → end` of length `t`.
  Only `(start, end)` is stored (16 bytes). The reduction `Rᵢ` depends on the
  column `i` **and** on the table id, which is what makes it a *rainbow* table
  (different columns use different reductions, limiting chain merges) and lets
  independent tables of the same length raise the success rate.
* **Reduction.** `Rᵢ` mixes 128 bits of the digest with a per-column /
  per-table constant and reduces modulo `62^L`; the 128-bit intermediate keeps
  the modulo bias negligible.
* **Tables on disk** are the chains sorted by endpoint (with duplicate
  endpoints removed — a "clean" table), so look-up is a binary search.
* **Look-up** is the classic rainbow walk: for each candidate column (last to
  first) rebuild the endpoint, binary-search it, and on a match regenerate the
  chain from its start to verify the real password.
* **Multithreading.** Table generation splits chains across a thread pool;
  the attack processes each hash on a worker thread. Both scale with cores
  (the statement notes multithreading is essentially required).

## Tuning (coverage vs. time)

Per table the cost is about `m · t` SHA-256 evaluations and `m · 16` bytes of
disk/RAM. The probability of cracking a given password of length `L` grows with
`m · t / 62^L` and with the number of independent tables for that length.

The key spaces are wildly different:

| L  | 62^L (≈)         |
|----|------------------|
| 6  | 5.7 × 10¹⁰       |
| 7  | 3.5 × 10¹²       |
| 8  | 2.2 × 10¹⁴       |
| 9  | 1.3 × 10¹⁶       |
| 10 | 8.4 × 10¹⁷       |

So length 6 is fully coverable, length 7 is coverable in part on one laptop,
and lengths 8–10 are only partially reachable. The defaults therefore spend
most of the budget on the short lengths, where cracks actually happen. To push
the success rate up:

* add more tables per length (increase `NTAB`), or
* increase `m` (more chains → more coverage, more disk/RAM), or
* increase `t` (longer chains → more coverage per byte, but slower look-up).

Measured throughput on a 4-core cloud VM was ≈ 12–13 million SHA-256/s; a
typical 8-core laptop does more, so the overnight budget is on the order of
10¹² evaluations — enough to cover length 6 strongly and length 7 partially.

## Repository layout

```
Makefile              build rules
build.sh              install deps + compile
build-tables.sh       preprocessing: generate the rainbow tables
README.md             this file
src/
  rainbow.hpp         core: indexing, reduction, chains, table I/O, look-up
  gen-table.cpp       preprocessing program
  attack.cpp          attack program
  sha256.{h,cpp}      SHA-256 (open source, Stephan Brumme — see headers)
  staticstring.hpp    provided helper
  random.hpp          provided helper
  passwd-utils.hpp    provided helper (used by gen/check-passwd)
  gen-passwd.cpp      provided tool
  check-passwd.cpp    provided tool
  misc/threadpool.hpp provided thread pool
```

## Credits / open-source libraries

* SHA-256 implementation by **Stephan Brumme**
  (<http://create.stephan-brumme.com/>), as provided with the assignment.
* `staticstring.hpp`, `random.hpp`, `passwd-utils.hpp`, `misc/threadpool.hpp`,
  `gen-passwd.cpp`, `check-passwd.cpp` are the assignment's provided code.
