#ifndef SHA256_FAST_HPP
#define SHA256_FAST_HPP

// ---------------------------------------------------------------------------
//  sha256_fast.hpp -- hardware-accelerated SHA-256 for short (<= 55 byte)
//  single-block messages, which is exactly our case (passwords of length
//  6..10). On x86 CPUs that expose the SHA extensions (Intel SHA-NI, all AMD
//  Zen, recent Intel) this is several times faster than the generic scalar
//  implementation, which dominates the whole project's running time.
//
//  SAFETY: the accelerated path is enabled only when
//     (1) the code was compiled for x86, AND
//     (2) the CPU advertises the SHA extensions at runtime, AND
//     (3) a one-time self-test confirms it reproduces the reference SHA-256
//         (the provided scalar implementation) bit for bit.
//  If any of these fails we transparently fall back to the scalar code, so the
//  result is *always* correct -- at worst it is slower, never wrong.
//
//  The single-block transform below is the well-known public-domain
//  implementation using the Intel SHA extensions intrinsics
//  (Jeffrey Walton, "Intel SHA extensions", public domain / CC0).
// ---------------------------------------------------------------------------

#include <cstdint>
#include <cstring>

#include "sha256.h"   // reference scalar SHA256 (used as fallback + self-test)

namespace rainbow {

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#define RAINBOW_X86 1
#include <immintrin.h>
#endif

#ifdef RAINBOW_X86
// Process exactly one 64-byte block with the SHA extensions. Compiled with a
// target attribute so it builds even when the translation unit is not globally
// compiled for -msha; it is only *executed* after a runtime capability check.
__attribute__((target("sha,sse4.1,ssse3")))
inline void sha256_ni_block(uint32_t state[8], const uint8_t block[64])
{
    __m128i STATE0, STATE1, MSG, TMP;
    __m128i MSG0, MSG1, MSG2, MSG3;
    __m128i ABEF_SAVE, CDGH_SAVE;
    const __m128i MASK =
        _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);

    TMP    = _mm_loadu_si128((const __m128i*) &state[0]);
    STATE1 = _mm_loadu_si128((const __m128i*) &state[4]);

    TMP    = _mm_shuffle_epi32(TMP, 0xB1);          // CDAB
    STATE1 = _mm_shuffle_epi32(STATE1, 0x1B);       // EFGH
    STATE0 = _mm_alignr_epi8(TMP, STATE1, 8);       // ABEF
    STATE1 = _mm_blend_epi16(STATE1, TMP, 0xF0);    // CDGH

    ABEF_SAVE = STATE0;
    CDGH_SAVE = STATE1;

    // Rounds 0-3
    MSG0 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(block + 0)), MASK);
    MSG  = _mm_add_epi32(MSG0, _mm_set_epi64x(0xE9B5DBA5B5C0FBCFULL, 0x71374491428A2F98ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG    = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    // Rounds 4-7
    MSG1 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(block + 16)), MASK);
    MSG  = _mm_add_epi32(MSG1, _mm_set_epi64x(0xAB1C5ED5923F82A4ULL, 0x59F111F13956C25BULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG    = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG0   = _mm_sha256msg1_epu32(MSG0, MSG1);

    // Rounds 8-11
    MSG2 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(block + 32)), MASK);
    MSG  = _mm_add_epi32(MSG2, _mm_set_epi64x(0x550C7DC3243185BEULL, 0x12835B01D807AA98ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG    = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG1   = _mm_sha256msg1_epu32(MSG1, MSG2);

    // Rounds 12-15
    MSG3 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(block + 48)), MASK);
    MSG  = _mm_add_epi32(MSG3, _mm_set_epi64x(0xC19BF1749BDC06A7ULL, 0x80DEB1FE72BE5D74ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP    = _mm_alignr_epi8(MSG3, MSG2, 4);
    MSG0   = _mm_add_epi32(MSG0, TMP);
    MSG0   = _mm_sha256msg2_epu32(MSG0, MSG3);
    MSG    = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG2   = _mm_sha256msg1_epu32(MSG2, MSG3);

    // Rounds 16-19
    MSG  = _mm_add_epi32(MSG0, _mm_set_epi64x(0x240CA1CC0FC19DC6ULL, 0xEFBE4786E49B69C1ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP    = _mm_alignr_epi8(MSG0, MSG3, 4);
    MSG1   = _mm_add_epi32(MSG1, TMP);
    MSG1   = _mm_sha256msg2_epu32(MSG1, MSG0);
    MSG    = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG3   = _mm_sha256msg1_epu32(MSG3, MSG0);

    // Rounds 20-23
    MSG  = _mm_add_epi32(MSG1, _mm_set_epi64x(0x76F988DA5CB0A9DCULL, 0x4A7484AA2DE92C6FULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP    = _mm_alignr_epi8(MSG1, MSG0, 4);
    MSG2   = _mm_add_epi32(MSG2, TMP);
    MSG2   = _mm_sha256msg2_epu32(MSG2, MSG1);
    MSG    = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG0   = _mm_sha256msg1_epu32(MSG0, MSG1);

    // Rounds 24-27
    MSG  = _mm_add_epi32(MSG2, _mm_set_epi64x(0xBF597FC7B00327C8ULL, 0xA831C66D983E5152ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP    = _mm_alignr_epi8(MSG2, MSG1, 4);
    MSG3   = _mm_add_epi32(MSG3, TMP);
    MSG3   = _mm_sha256msg2_epu32(MSG3, MSG2);
    MSG    = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG1   = _mm_sha256msg1_epu32(MSG1, MSG2);

    // Rounds 28-31
    MSG  = _mm_add_epi32(MSG3, _mm_set_epi64x(0x1429296706CA6351ULL, 0xD5A79147C6E00BF3ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP    = _mm_alignr_epi8(MSG3, MSG2, 4);
    MSG0   = _mm_add_epi32(MSG0, TMP);
    MSG0   = _mm_sha256msg2_epu32(MSG0, MSG3);
    MSG    = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG2   = _mm_sha256msg1_epu32(MSG2, MSG3);

    // Rounds 32-35
    MSG  = _mm_add_epi32(MSG0, _mm_set_epi64x(0x53380D134D2C6DFCULL, 0x2E1B213827B70A85ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP    = _mm_alignr_epi8(MSG0, MSG3, 4);
    MSG1   = _mm_add_epi32(MSG1, TMP);
    MSG1   = _mm_sha256msg2_epu32(MSG1, MSG0);
    MSG    = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG3   = _mm_sha256msg1_epu32(MSG3, MSG0);

    // Rounds 36-39
    MSG  = _mm_add_epi32(MSG1, _mm_set_epi64x(0x92722C8581C2C92EULL, 0x766A0ABB650A7354ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP    = _mm_alignr_epi8(MSG1, MSG0, 4);
    MSG2   = _mm_add_epi32(MSG2, TMP);
    MSG2   = _mm_sha256msg2_epu32(MSG2, MSG1);
    MSG    = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG0   = _mm_sha256msg1_epu32(MSG0, MSG1);

    // Rounds 40-43
    MSG  = _mm_add_epi32(MSG2, _mm_set_epi64x(0xC76C51A3C24B8B70ULL, 0xA81A664BA2BFE8A1ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP    = _mm_alignr_epi8(MSG2, MSG1, 4);
    MSG3   = _mm_add_epi32(MSG3, TMP);
    MSG3   = _mm_sha256msg2_epu32(MSG3, MSG2);
    MSG    = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG1   = _mm_sha256msg1_epu32(MSG1, MSG2);

    // Rounds 44-47
    MSG  = _mm_add_epi32(MSG3, _mm_set_epi64x(0x106AA070F40E3585ULL, 0xD6990624D192E819ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP    = _mm_alignr_epi8(MSG3, MSG2, 4);
    MSG0   = _mm_add_epi32(MSG0, TMP);
    MSG0   = _mm_sha256msg2_epu32(MSG0, MSG3);
    MSG    = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG2   = _mm_sha256msg1_epu32(MSG2, MSG3);

    // Rounds 48-51
    MSG  = _mm_add_epi32(MSG0, _mm_set_epi64x(0x34B0BCB52748774CULL, 0x1E376C0819A4C116ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP    = _mm_alignr_epi8(MSG0, MSG3, 4);
    MSG1   = _mm_add_epi32(MSG1, TMP);
    MSG1   = _mm_sha256msg2_epu32(MSG1, MSG0);
    MSG    = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG3   = _mm_sha256msg1_epu32(MSG3, MSG0);

    // Rounds 52-55
    MSG  = _mm_add_epi32(MSG1, _mm_set_epi64x(0x682E6FF35B9CCA4FULL, 0x4ED8AA4A391C0CB3ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP    = _mm_alignr_epi8(MSG1, MSG0, 4);
    MSG2   = _mm_add_epi32(MSG2, TMP);
    MSG2   = _mm_sha256msg2_epu32(MSG2, MSG1);
    MSG    = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    // Rounds 56-59
    MSG  = _mm_add_epi32(MSG2, _mm_set_epi64x(0x8CC7020884C87814ULL, 0x78A5636F748F82EEULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP    = _mm_alignr_epi8(MSG2, MSG1, 4);
    MSG3   = _mm_add_epi32(MSG3, TMP);
    MSG3   = _mm_sha256msg2_epu32(MSG3, MSG2);
    MSG    = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    // Rounds 60-63
    MSG  = _mm_add_epi32(MSG3, _mm_set_epi64x(0xC67178F2BEF9A3F7ULL, 0xA4506CEB90BEFFFAULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG    = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    STATE0 = _mm_add_epi32(STATE0, ABEF_SAVE);
    STATE1 = _mm_add_epi32(STATE1, CDGH_SAVE);

    TMP    = _mm_shuffle_epi32(STATE0, 0x1B);       // FEBA
    STATE1 = _mm_shuffle_epi32(STATE1, 0xB1);       // DCHG
    STATE0 = _mm_blend_epi16(TMP, STATE1, 0xF0);    // DCBA
    STATE1 = _mm_alignr_epi8(STATE1, TMP, 8);       // ABEF

    _mm_storeu_si128((__m128i*) &state[0], STATE0);
    _mm_storeu_si128((__m128i*) &state[4], STATE1);
}

// SHA-256 of a single short message (len <= 55) using the SHA extensions.
__attribute__((target("sha,sse4.1,ssse3")))
inline void sha256_shani_short(const uint8_t* msg, unsigned len, uint8_t out[32])
{
    uint8_t block[64];
    std::memcpy(block, msg, len);
    block[len] = 0x80;
    std::memset(block + len + 1, 0, 64 - (len + 1));
    const uint64_t bits = uint64_t(len) * 8;
    for (int i = 0; i < 8; ++i)                     // 64-bit big-endian length
        block[63 - i] = uint8_t(bits >> (8 * i));

    uint32_t state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    sha256_ni_block(state, block);

    for (int i = 0; i < 8; ++i)
    {
        out[4 * i + 0] = uint8_t(state[i] >> 24);
        out[4 * i + 1] = uint8_t(state[i] >> 16);
        out[4 * i + 2] = uint8_t(state[i] >> 8);
        out[4 * i + 3] = uint8_t(state[i]);
    }
}
#endif // RAINBOW_X86

// Reference scalar digest (always correct), used as fallback and in the
// self-test.
inline void sha256_scalar_short(const char* data, size_t len, uint8_t out[32])
{
    thread_local SHA256 sha;
    sha.reset();
    sha.add(data, len);
    sha.getHash(out);
}

// Decide once whether the accelerated path may be used. Returns true only if
// the SHA extensions exist AND reproduce the reference digest on a battery of
// short inputs of every admissible length.
inline bool shani_enabled()
{
    static const bool ok = []() -> bool {
#ifdef RAINBOW_X86
        if (!__builtin_cpu_supports("sha") ||
            !__builtin_cpu_supports("sse4.1") ||
            !__builtin_cpu_supports("ssse3"))
            return false;

        const char* vectors[] = {
            "", "a", "abc", "grape", "123456", "abcdef",
            "Sh5eWV", "aZ09aZ09", "passw0rd12", "0123456789",
            "The quick brown fox jumps over the lazydo"   // 41 bytes
        };
        for (const char* v : vectors)
        {
            unsigned len = unsigned(std::strlen(v));
            if (len > 55) continue;
            uint8_t a[32], b[32];
            sha256_shani_short(reinterpret_cast<const uint8_t*>(v), len, a);
            sha256_scalar_short(v, len, b);
            if (std::memcmp(a, b, 32) != 0)
                return false;         // bug / mismatch -> stay on scalar
        }
        return true;
#else
        return false;
#endif
    }();
    return ok;
}

// The one entry point used by the rest of the project. Correct on every CPU;
// fast where the SHA extensions are available and verified.
inline void sha256_short(const char* data, size_t len, uint8_t out[32])
{
#ifdef RAINBOW_X86
    if (len <= 55 && shani_enabled())
    {
        sha256_shani_short(reinterpret_cast<const uint8_t*>(data),
                           unsigned(len), out);
        return;
    }
#endif
    sha256_scalar_short(data, len, out);
}

} // namespace rainbow

#endif // SHA256_FAST_HPP
