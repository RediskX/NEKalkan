// NEKalkan — хэш-функции.
#include "hash.h"
#include "legacy.h"

namespace nek {

#include "streebog_tables.inc"

static inline u32 rol32(u32 x, int n) { return (x << n) | (x >> (32 - n)); }
static inline u32 ror32(u32 x, int n) { return (x >> n) | (x << (32 - n)); }
static inline u64 ror64(u64 x, int n) { return (x >> n) | (x << (64 - n)); }

static inline u32 be32(const u8* p) { return ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) | p[3]; }
static inline u64 be64(const u8* p) { return ((u64)be32(p) << 32) | be32(p + 4); }
static inline void put_be32(u8* p, u32 v) { p[0] = (u8)(v >> 24); p[1] = (u8)(v >> 16); p[2] = (u8)(v >> 8); p[3] = (u8)v; }
static inline void put_be64(u8* p, u64 v) { put_be32(p, (u32)(v >> 32)); put_be32(p + 4, (u32)v); }
static inline u64 le64(const u8* p) {
    u64 v = 0;
    for (int i = 7; i >= 0; --i) v = (v << 8) | p[i];
    return v;
}
static inline void put_le64(u8* p, u64 v) { for (int i = 0; i < 8; ++i) { p[i] = (u8)v; v >>= 8; } }

size_t hash_size(HashAlg a) {
    switch (a) {
        case H_SHA1: return 20;
        case H_SHA256: return 32;
        case H_SHA384: return 48;
        case H_SHA512: return 64;
        case H_STREEBOG256: return 32;
        case H_STREEBOG512: return 64;
        case H_GOST94: return 32;
        default: return 0;
    }
}

size_t hash_block(HashAlg a) {
    switch (a) {
        case H_SHA1: case H_SHA256: return 64;
        case H_SHA384: case H_SHA512: return 128;
        case H_STREEBOG256: case H_STREEBOG512: return 64;
        default: return 0;
    }
}

// ---- SHA-1 -----------------------------------------------------------------

static void sha1_block(u32 s[5], const u8* p) {
    u32 w[80];
    for (int i = 0; i < 16; ++i) w[i] = be32(p + 4 * i);
    for (int i = 16; i < 80; ++i) w[i] = rol32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    u32 a = s[0], b = s[1], c = s[2], d = s[3], e = s[4];
    for (int i = 0; i < 80; ++i) {
        u32 f, k;
        if (i < 20) { f = (b & c) | (~b & d); k = 0x5A827999; }
        else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
        else { f = b ^ c ^ d; k = 0xCA62C1D6; }
        u32 t = rol32(a, 5) + f + e + k + w[i];
        e = d; d = c; c = rol32(b, 30); b = a; a = t;
    }
    s[0] += a; s[1] += b; s[2] += c; s[3] += d; s[4] += e;
}

// ---- SHA-256 ---------------------------------------------------------------

static const u32 K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

static void sha256_block(u32 s[8], const u8* p) {
    u32 w[64];
    for (int i = 0; i < 16; ++i) w[i] = be32(p + 4 * i);
    for (int i = 16; i < 64; ++i) {
        u32 s0 = ror32(w[i - 15], 7) ^ ror32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        u32 s1 = ror32(w[i - 2], 17) ^ ror32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    u32 a = s[0], b = s[1], c = s[2], d = s[3], e = s[4], f = s[5], g = s[6], h = s[7];
    for (int i = 0; i < 64; ++i) {
        u32 S1 = ror32(e, 6) ^ ror32(e, 11) ^ ror32(e, 25);
        u32 ch = (e & f) ^ (~e & g);
        u32 t1 = h + S1 + ch + K256[i] + w[i];
        u32 S0 = ror32(a, 2) ^ ror32(a, 13) ^ ror32(a, 22);
        u32 mj = (a & b) ^ (a & c) ^ (b & c);
        u32 t2 = S0 + mj;
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    s[0] += a; s[1] += b; s[2] += c; s[3] += d; s[4] += e; s[5] += f; s[6] += g; s[7] += h;
}

// ---- SHA-512 / SHA-384 -----------------------------------------------------

static const u64 K512[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};

static void sha512_block(u64 s[8], const u8* p) {
    u64 w[80];
    for (int i = 0; i < 16; ++i) w[i] = be64(p + 8 * i);
    for (int i = 16; i < 80; ++i) {
        u64 s0 = ror64(w[i - 15], 1) ^ ror64(w[i - 15], 8) ^ (w[i - 15] >> 7);
        u64 s1 = ror64(w[i - 2], 19) ^ ror64(w[i - 2], 61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    u64 a = s[0], b = s[1], c = s[2], d = s[3], e = s[4], f = s[5], g = s[6], h = s[7];
    for (int i = 0; i < 80; ++i) {
        u64 S1 = ror64(e, 14) ^ ror64(e, 18) ^ ror64(e, 41);
        u64 ch = (e & f) ^ (~e & g);
        u64 t1 = h + S1 + ch + K512[i] + w[i];
        u64 S0 = ror64(a, 28) ^ ror64(a, 34) ^ ror64(a, 39);
        u64 mj = (a & b) ^ (a & c) ^ (b & c);
        u64 t2 = S0 + mj;
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    s[0] += a; s[1] += b; s[2] += c; s[3] += d; s[4] += e; s[5] += f; s[6] += g; s[7] += h;
}

// ---- Стрибог -----------------------------------------------------------------

typedef u64 W8[8];

static inline void lps(W8 out, const W8 in) {
    for (int j = 0; j < 8; ++j) {
        int sh = 8 * j;
        out[j] = STREEBOG_T[0][(in[0] >> sh) & 0xFF] ^ STREEBOG_T[1][(in[1] >> sh) & 0xFF] ^
                 STREEBOG_T[2][(in[2] >> sh) & 0xFF] ^ STREEBOG_T[3][(in[3] >> sh) & 0xFF] ^
                 STREEBOG_T[4][(in[4] >> sh) & 0xFF] ^ STREEBOG_T[5][(in[5] >> sh) & 0xFF] ^
                 STREEBOG_T[6][(in[6] >> sh) & 0xFF] ^ STREEBOG_T[7][(in[7] >> sh) & 0xFF];
    }
}

// g(h, N, m)
static void streebog_g(W8 h, const W8 n, const W8 m) {
    W8 k, t, x;
    for (int i = 0; i < 8; ++i) x[i] = n[i] ^ h[i];
    lps(k, x);                                           // K1 = LPS(N ^ h)
    W8 st;
    for (int i = 0; i < 8; ++i) st[i] = k[i] ^ m[i];
    for (int r = 0; r < 12; ++r) {
        lps(t, st);
        for (int i = 0; i < 8; ++i) x[i] = k[i] ^ STREEBOG_C[r][i];
        lps(k, x);                                       // следующий раундовый ключ
        for (int i = 0; i < 8; ++i) st[i] = t[i] ^ k[i];
    }
    for (int i = 0; i < 8; ++i) h[i] = st[i] ^ h[i] ^ m[i];
}

static void add512(W8 a, const W8 b) {
    u64 carry = 0;
    for (int i = 0; i < 8; ++i) {
        u64 s = a[i] + b[i];
        u64 c1 = s < a[i];
        u64 s2 = s + carry;
        u64 c2 = s2 < s;
        a[i] = s2;
        carry = c1 | c2;
    }
}

static void streebog_block(HashCtx& c, const u8* p) {
    W8 m;
    for (int i = 0; i < 8; ++i) m[i] = le64(p + 8 * i);
    streebog_g(c.st.gost.h, c.st.gost.n, m);
    W8 v512 = {512, 0, 0, 0, 0, 0, 0, 0};
    add512(c.st.gost.n, v512);
    add512(c.st.gost.sigma, m);
}

// ---- общий интерфейс -----------------------------------------------------------

void hash_init(HashCtx& c, HashAlg a) {
    memset(&c, 0, sizeof(c));
    c.alg = a;
    switch (a) {
        case H_SHA1:
            c.st.s32[0] = 0x67452301; c.st.s32[1] = 0xEFCDAB89; c.st.s32[2] = 0x98BADCFE;
            c.st.s32[3] = 0x10325476; c.st.s32[4] = 0xC3D2E1F0;
            break;
        case H_SHA256: {
            static const u32 iv[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
            for (int i = 0; i < 8; ++i) c.st.s32[i] = iv[i];
            break;
        }
        case H_SHA384: {
            static const u64 iv[8] = {0xcbbb9d5dc1059ed8ULL, 0x629a292a367cd507ULL, 0x9159015a3070dd17ULL,
                                      0x152fecd8f70e5939ULL, 0x67332667ffc00b31ULL, 0x8eb44a8768581511ULL,
                                      0xdb0c2e0d64f98fa7ULL, 0x47b5481dbefa4fa4ULL};
            for (int i = 0; i < 8; ++i) c.st.s64[i] = iv[i];
            break;
        }
        case H_SHA512: {
            static const u64 iv[8] = {0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL,
                                      0xa54ff53a5f1d36f1ULL, 0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
                                      0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};
            for (int i = 0; i < 8; ++i) c.st.s64[i] = iv[i];
            break;
        }
        case H_STREEBOG256:
            for (int i = 0; i < 8; ++i) c.st.gost.h[i] = 0x0101010101010101ULL;
            break;
        default:
            break;
    }
}

static void block_dispatch(HashCtx& c, const u8* p) {
    switch (c.alg) {
        case H_SHA1: sha1_block(c.st.s32, p); break;
        case H_SHA256: sha256_block(c.st.s32, p); break;
        case H_SHA384: case H_SHA512: sha512_block(c.st.s64, p); break;
        case H_STREEBOG256: case H_STREEBOG512: streebog_block(c, p); break;
        default: break;
    }
}

void hash_update(HashCtx& c, const void* data, size_t len) {
    const u8* p = (const u8*)data;
    size_t bs = hash_block(c.alg);
    if (!bs) return;
    c.total += len;
    if (c.blen) {
        size_t take = bs - c.blen;
        if (take > len) take = len;
        memcpy(c.buf + c.blen, p, take);
        c.blen += take; p += take; len -= take;
        if (c.blen < bs) return;
        block_dispatch(c, c.buf);
        c.blen = 0;
    }
    while (len >= bs) { block_dispatch(c, p); p += bs; len -= bs; }
    if (len) { memcpy(c.buf, p, len); c.blen = len; }
}

void hash_final(HashCtx& c, u8* out) {
    switch (c.alg) {
        case H_SHA1: case H_SHA256: {
            u64 bits = c.total * 8;
            u8 pad[72];
            size_t padlen = (c.blen < 56) ? 56 - c.blen : 120 - c.blen;
            memset(pad, 0, sizeof(pad));
            pad[0] = 0x80;
            u64 saved = c.total;
            hash_update(c, pad, padlen);
            u8 lenb[8];
            put_be64(lenb, bits);
            hash_update(c, lenb, 8);
            c.total = saved;
            size_t words = (c.alg == H_SHA1) ? 5 : 8;
            for (size_t i = 0; i < words; ++i) put_be32(out + 4 * i, c.st.s32[i]);
            break;
        }
        case H_SHA384: case H_SHA512: {
            u64 bits = c.total * 8;
            u8 pad[144];
            size_t padlen = (c.blen < 112) ? 112 - c.blen : 240 - c.blen;
            memset(pad, 0, sizeof(pad));
            pad[0] = 0x80;
            u64 saved = c.total;
            hash_update(c, pad, padlen);
            u8 lenb[16] = {0};
            put_be64(lenb + 8, bits);
            hash_update(c, lenb, 16);
            c.total = saved;
            size_t words = (c.alg == H_SHA384) ? 6 : 8;
            for (size_t i = 0; i < words; ++i) put_be64(out + 8 * i, c.st.s64[i]);
            break;
        }
        case H_STREEBOG256: case H_STREEBOG512: {
            u8 last[64];
            memset(last, 0, 64);
            memcpy(last, c.buf, c.blen);
            last[c.blen] = 0x01;
            W8 m;
            for (int i = 0; i < 8; ++i) m[i] = le64(last + 8 * i);
            streebog_g(c.st.gost.h, c.st.gost.n, m);
            W8 len = {(u64)c.blen * 8, 0, 0, 0, 0, 0, 0, 0};
            add512(c.st.gost.n, len);
            add512(c.st.gost.sigma, m);
            W8 zero = {0, 0, 0, 0, 0, 0, 0, 0};
            streebog_g(c.st.gost.h, zero, c.st.gost.n);
            streebog_g(c.st.gost.h, zero, c.st.gost.sigma);
            u8 full[64];
            for (int i = 0; i < 8; ++i) put_le64(full + 8 * i, c.st.gost.h[i]);
            if (c.alg == H_STREEBOG512) memcpy(out, full, 64);
            else memcpy(out, full + 32, 32);
            break;
        }
        default:
            break;
    }
}

void hash_data(HashAlg a, const void* data, size_t len, u8* out) {
    if (a == H_GOST94) { gost341194_kz(Span((const u8*)data, len), out); return; }
    HashCtx c;
    hash_init(c, a);
    hash_update(c, data, len);
    hash_final(c, out);
    wipe(&c, sizeof(c));
}

void hmac(HashAlg a, Span key, Span data, u8* out) {
    size_t bs = hash_block(a), hs = hash_size(a);
    u8 k[128];
    u8 ipad[128], opad[128];
    memset(k, 0, sizeof(k));
    if (key.n > bs) hash_data(a, key, k); else if (key.n) memcpy(k, key.p, key.n);
    for (size_t i = 0; i < bs; ++i) { ipad[i] = k[i] ^ 0x36; opad[i] = k[i] ^ 0x5c; }
    u8 inner[64];
    HashCtx c;
    hash_init(c, a);
    hash_update(c, ipad, bs);
    hash_update(c, data.p, data.n);
    hash_final(c, inner);
    hash_init(c, a);
    hash_update(c, opad, bs);
    hash_update(c, inner, hs);
    hash_final(c, out);
    wipe(k, sizeof(k)); wipe(ipad, sizeof(ipad)); wipe(opad, sizeof(opad)); wipe(&c, sizeof(c));
}

}  // namespace nek
