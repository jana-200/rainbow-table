#ifndef RAINBOW_HPP
#define RAINBOW_HPP

// ---------------------------------------------------------------------------
//  rainbow.hpp -- core of the rainbow-table attack against SHA-256 hashes of
//  alphanumeric passwords (length 6..10, no salt, single hash pass).
//
//  The whole project is built around the following conventions, shared by the
//  preprocessing program (gen-table) and the attack program (attack):
//
//   * We build *one rainbow table per password length* (the statement allows
//     it for simplicity).  A table for length L covers the key space
//         N(L) = 62^L
//     where 62 is the size of the alphanumeric alphabet.
//
//   * A password of length L is identified with an integer index in
//     [0, 62^L) through a plain base-62 encoding (see index_to_password /
//     password_to_index).  The alphabet is exactly the one used by the
//     teacher's gen-passwd, so every password the teacher can generate has a
//     unique index, and conversely.
//
//   * A chain is   start --H,R0--> p1 --H,R1--> p2 --...--> end
//     i.e. columns 0..t.  Column c holds password index P_c with
//         P_0   = start
//         P_c+1 = R_c( SHA256( password(P_c) ) )
//     and the stored endpoint is P_t.  There are t hash evaluations and t
//     reduction steps per chain.  Each reduction R_c depends on the column c
//     AND on the table id, so different columns / tables use different
//     reduction families (this is what makes it a *rainbow* table and limits
//     chain merges).
//
//   * On disk a table is a small binary header followed by the chains sorted
//     by endpoint, which makes look-up a binary search.
// ---------------------------------------------------------------------------

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <fstream>
#include <stdexcept>
#include <algorithm>

#include "sha256.h"

namespace rainbow {

// The alphabet is the very one used by the provided gen-passwd / passwd-utils.
// Its ordering is irrelevant for coverage (it is a permutation of the 62
// alphanumeric characters); we keep it identical only for clarity.
inline constexpr char ALPHABET[] =
    "azertyuiopqsdfghjklmwxcvbnAZERTYUIOPQSDFGHJKLMWXCVBN1234567890";
inline constexpr uint64_t ALPHABET_SIZE = 62;

inline constexpr int MIN_LEN = 6;
inline constexpr int MAX_LEN = 10;

// Number of candidate passwords of a given length: 62^L. 62^10 ~= 8.39e17
// fits comfortably in a uint64_t (< 2^63), so a single integer indexes any
// password of any admissible length.
inline uint64_t keyspace(int length)
{
    uint64_t n = 1;
    for (int i = 0; i < length; ++i)
        n *= ALPHABET_SIZE;
    return n;
}

// ---------------------------------------------------------------------------
//  Index  <->  password
// ---------------------------------------------------------------------------

// Writes the password of index `idx` (length `length`) into `out` (which must
// hold at least `length` bytes). No terminating '\0' is written; callers pass
// the explicit length to SHA256::add.
inline void index_to_password(uint64_t idx, int length, char* out)
{
    for (int i = 0; i < length; ++i)
    {
        out[i] = ALPHABET[idx % ALPHABET_SIZE];
        idx /= ALPHABET_SIZE;
    }
}

// Inverse mapping, handy for tests. Returns 0 on success.
inline uint64_t password_to_index(const char* pwd, int length)
{
    // reverse lookup table built once.
    static int8_t lut[256];
    static bool init = false;
    if (!init)
    {
        std::fill(std::begin(lut), std::end(lut), int8_t(-1));
        for (uint64_t i = 0; i < ALPHABET_SIZE; ++i)
            lut[(unsigned char) ALPHABET[i]] = (int8_t) i;
        init = true;
    }

    uint64_t idx = 0, place = 1;
    for (int i = 0; i < length; ++i)
    {
        int8_t v = lut[(unsigned char) pwd[i]];
        if (v < 0)
            throw std::runtime_error("character outside the password policy");
        idx += uint64_t(v) * place;
        place *= ALPHABET_SIZE;
    }
    return idx;
}

// ---------------------------------------------------------------------------
//  SHA-256 helper: raw 32-byte digest, no hex string allocation.
// ---------------------------------------------------------------------------

inline void sha256_raw(const char* data, size_t len, uint8_t digest[SHA256::HashBytes])
{
    // A per-thread SHA256 object avoids re-allocating state and makes the hot
    // loops thread-safe when used from the thread pool.
    thread_local SHA256 sha;
    sha.reset();
    sha.add(data, len);
    sha.getHash(digest);
}

// ---------------------------------------------------------------------------
//  Reduction function R_{column, table}: digest -> password index in [0, N).
//
//  We mix 128 bits of the digest with a per-column / per-table constant so
//  that two different columns (or tables) almost never apply the same
//  reduction. The 128-bit intermediate value makes the modulo bias negligible
//  for every admissible key space.
// ---------------------------------------------------------------------------

inline uint64_t load64(const uint8_t* p)
{
    uint64_t v;
    std::memcpy(&v, p, sizeof(v));
    return v;
}

inline uint64_t reduce(const uint8_t digest[SHA256::HashBytes],
                       uint64_t column, uint64_t table_id, uint64_t N)
{
    const uint64_t w0 = load64(digest);
    const uint64_t w1 = load64(digest + 8);

    __uint128_t v = ((__uint128_t) w0 << 64) | w1;
    // distinct, well-spread offset per (column, table)
    uint64_t salt = (column * 0x9E3779B97F4A7C15ULL)
                  ^ (table_id * 0xC2B2AE3D27D4EB4FULL + 0x165667B19E3779F9ULL);
    v += (__uint128_t) salt * 0xFF51AFD7ED558CCDULL;

    return (uint64_t) (v % N);
}

// ---------------------------------------------------------------------------
//  A single chain stored on disk / in memory.
// ---------------------------------------------------------------------------

#pragma pack(push, 1)
struct Chain
{
    uint64_t start;
    uint64_t end;
};
#pragma pack(pop)

// Compute the endpoint of the chain starting at `start`, for a table of
// `length`, chain length `t`, identified by `table_id`.
inline uint64_t chain_endpoint(uint64_t start, uint64_t t,
                               int length, uint64_t table_id, uint64_t N)
{
    char buf[MAX_LEN];
    uint8_t digest[SHA256::HashBytes];

    uint64_t cur = start;
    for (uint64_t c = 0; c < t; ++c)
    {
        index_to_password(cur, length, buf);
        sha256_raw(buf, length, digest);
        cur = reduce(digest, c, table_id, N);
    }
    return cur;
}

// ---------------------------------------------------------------------------
//  On-disk table format.
// ---------------------------------------------------------------------------

inline constexpr char   TABLE_MAGIC[4] = {'R', 'T', 'B', 'L'};
inline constexpr uint32_t TABLE_VERSION = 1;

#pragma pack(push, 1)
struct TableHeader
{
    char     magic[4];     // "RTBL"
    uint32_t version;      // TABLE_VERSION
    uint32_t length;       // password length L
    uint32_t table_id;     // reduction family id
    uint64_t t;            // chain length
    uint64_t N;            // key space (62^L)
    uint64_t count;        // number of chains
};
#pragma pack(pop)

// A table fully loaded in memory, ready for look-up. Chains are sorted by
// endpoint.
struct Table
{
    uint32_t length = 0;
    uint32_t table_id = 0;
    uint64_t t = 0;
    uint64_t N = 0;
    std::vector<Chain> chains;   // sorted by .end

    // approximate RAM footprint of the loaded chains, in bytes
    uint64_t memory_bytes() const { return chains.size() * sizeof(Chain); }
};

inline void write_table(const std::string& path, uint32_t length,
                        uint32_t table_id, uint64_t t, uint64_t N,
                        std::vector<Chain>& chains)
{
    // Sort by endpoint so that the attack can binary-search, and drop chains
    // that collide on the same endpoint (a "clean" table: merged chains carry
    // no extra coverage but cost look-up time and disk space).
    std::sort(chains.begin(), chains.end(),
              [](const Chain& a, const Chain& b) { return a.end < b.end; });
    chains.erase(std::unique(chains.begin(), chains.end(),
                             [](const Chain& a, const Chain& b)
                             { return a.end == b.end; }),
                 chains.end());

    std::ofstream out(path, std::ios::binary);
    if (!out)
        throw std::runtime_error("cannot open table file for writing: " + path);

    TableHeader h;
    std::memcpy(h.magic, TABLE_MAGIC, 4);
    h.version  = TABLE_VERSION;
    h.length   = length;
    h.table_id = table_id;
    h.t        = t;
    h.N        = N;
    h.count    = chains.size();

    out.write(reinterpret_cast<const char*>(&h), sizeof(h));
    out.write(reinterpret_cast<const char*>(chains.data()),
              std::streamsize(chains.size() * sizeof(Chain)));
    if (!out)
        throw std::runtime_error("error while writing table file: " + path);
}

inline Table load_table(const std::string& path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in)
        throw std::runtime_error("cannot open table file for reading: " + path);

    TableHeader h;
    in.read(reinterpret_cast<char*>(&h), sizeof(h));
    if (!in || std::memcmp(h.magic, TABLE_MAGIC, 4) != 0)
        throw std::runtime_error("not a rainbow table file: " + path);
    if (h.version != TABLE_VERSION)
        throw std::runtime_error("unsupported table version: " + path);

    Table tb;
    tb.length   = h.length;
    tb.table_id = h.table_id;
    tb.t        = h.t;
    tb.N        = h.N;
    tb.chains.resize(h.count);
    in.read(reinterpret_cast<char*>(tb.chains.data()),
            std::streamsize(h.count * sizeof(Chain)));
    if (!in)
        throw std::runtime_error("truncated table file: " + path);

    return tb;
}

// ---------------------------------------------------------------------------
//  Look-up: try to crack a single digest using one table.
//
//  Returns true and fills `out` with the password if found. The classic
//  rainbow walk: for each candidate column c (from the last to the first) we
//  assume the secret sits at column c, rebuild the endpoint, binary-search it,
//  and on a match regenerate the chain from its stored start to verify.
// ---------------------------------------------------------------------------

inline bool crack_with_table(const uint8_t target[SHA256::HashBytes],
                             const Table& tb, std::string& out)
{
    const uint64_t N = tb.N;
    const uint64_t t = tb.t;
    const int      L = int(tb.length);
    const uint64_t id = tb.table_id;

    char buf[MAX_LEN];
    uint8_t digest[SHA256::HashBytes];

    for (int64_t c = int64_t(t) - 1; c >= 0; --c)
    {
        // Rebuild the endpoint assuming the secret is at column c.
        uint64_t cur = reduce(target, uint64_t(c), id, N);
        for (uint64_t d = uint64_t(c) + 1; d < t; ++d)
        {
            index_to_password(cur, L, buf);
            sha256_raw(buf, L, digest);
            cur = reduce(digest, d, id, N);
        }

        // Binary-search every chain whose endpoint equals `cur`.
        Chain probe; probe.start = 0; probe.end = cur;
        auto range = std::equal_range(tb.chains.begin(), tb.chains.end(), probe,
                                      [](const Chain& a, const Chain& b)
                                      { return a.end < b.end; });

        for (auto it = range.first; it != range.second; ++it)
        {
            // Regenerate from the stored start up to column c.
            uint64_t p = it->start;
            for (uint64_t k = 0; k < uint64_t(c); ++k)
            {
                index_to_password(p, L, buf);
                sha256_raw(buf, L, digest);
                p = reduce(digest, k, id, N);
            }
            // Candidate password sits at column c; verify its hash.
            index_to_password(p, L, buf);
            sha256_raw(buf, L, digest);
            if (std::memcmp(digest, target, SHA256::HashBytes) == 0)
            {
                out.assign(buf, size_t(L));
                return true;
            }
            // otherwise: false alarm (different chain collided on the endpoint)
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
//  Hex <-> bytes helpers for the hash files.
// ---------------------------------------------------------------------------

// Parses 64 lowercase hex characters into 32 bytes. Returns false on malformed
// input.
inline bool hex_to_digest(const std::string& hex, uint8_t digest[SHA256::HashBytes])
{
    if (hex.size() != size_t(2 * SHA256::HashBytes))
        return false;

    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (int i = 0; i < SHA256::HashBytes; ++i)
    {
        int hi = nib(hex[2 * i]);
        int lo = nib(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        digest[i] = uint8_t((hi << 4) | lo);
    }
    return true;
}

} // namespace rainbow

#endif // RAINBOW_HPP
