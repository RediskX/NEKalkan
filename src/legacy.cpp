// NEKalkan — устаревшие ГОСТ: 28147-89, 34.11-94 (КЗ-презентация).
#include "legacy.h"
#include "asn1.h"
#include "gost3410.h"

namespace nek {

static const u8 SBOX_TEST[8][16] = {
    {4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3},
    {14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9},
    {5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11},
    {7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3},
    {6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2},
    {4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14},
    {13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12},
    {1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12},
};

static const u8 SBOX_CRYPTOPRO[8][16] = {
    {10, 4, 5, 6, 8, 1, 3, 7, 13, 12, 14, 0, 9, 2, 11, 15},
    {5, 15, 4, 0, 2, 13, 11, 9, 1, 7, 6, 3, 12, 14, 10, 8},
    {7, 15, 12, 14, 9, 4, 1, 0, 3, 11, 5, 2, 6, 10, 8, 13},
    {4, 10, 7, 12, 0, 15, 2, 8, 14, 1, 6, 5, 13, 11, 9, 3},
    {7, 6, 4, 11, 9, 12, 2, 10, 1, 8, 0, 14, 15, 13, 3, 5},
    {7, 6, 2, 4, 13, 9, 15, 0, 10, 1, 5, 11, 8, 14, 12, 3},
    {13, 14, 4, 1, 7, 0, 5, 10, 3, 12, 8, 15, 6, 2, 9, 11},
    {1, 3, 10, 9, 5, 11, 4, 15, 8, 6, 7, 14, 13, 0, 2, 12},
};

static inline u32 be32(const u8* p) { return ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) | p[3]; }
static inline void put_be32(u8* p, u32 v) { p[0] = (u8)(v >> 24); p[1] = (u8)(v >> 16); p[2] = (u8)(v >> 8); p[3] = (u8)v; }

static inline u32 g_func(u32 sub, u32 w, const u8 (*sb)[16]) {
    u32 t = sub + w;
    u32 out = 0;
    for (int j = 0; j < 8; ++j) out |= (u32)sb[j][(t >> (4 * j)) & 0xF] << (4 * j);
    return (out << 11) | (out >> 21);
}

void gost28147_encrypt_block(const u8 key[32], const u8 in[8], u8 out[8], Gost94Sbox sbox) {
    const u8 (*sb)[16] = sbox == GOST94_CRYPTOPRO ? SBOX_CRYPTOPRO : SBOX_TEST;
    u32 k[8];
    for (int i = 0; i < 8; ++i) k[i] = be32(key + 4 * i);
    u32 n1 = be32(in), n2 = be32(in + 4);
    for (int i = 0; i < 32; ++i) {
        int idx = i < 24 ? (i & 7) : 31 - i;
        u32 g = g_func(k[idx], n2, sb);
        if (i == 31) n1 ^= g;
        else { u32 t = n2; n2 = n1 ^ g; n1 = t; }
    }
    put_be32(out, n1);
    put_be32(out + 4, n2);
}

// ---- ГОСТ Р 34.11-94 ------------------------------------------------------------------------

static const u8 C3[32] = {0xff, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0xff, 0x00, 0xff, 0xff, 0x00,
                          0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00};

static void xor32(u8* r, const u8* a, const u8* b) { for (int i = 0; i < 32; ++i) r[i] = a[i] ^ b[i]; }

static void A(const u8* x, u8* out) {
    // x4=x[0:8], x3=x[8:16], x2=x[16:24], x1=x[24:32]; out = (x1^x2) || x4 || x3 || x2
    for (int i = 0; i < 8; ++i) out[i] = x[24 + i] ^ x[16 + i];
    memcpy(out + 8, x, 8);
    memcpy(out + 16, x + 8, 8);
    memcpy(out + 24, x + 16, 8);
}

static void Pperm(const u8* x, u8* out) {
    // P: out[4*i + j] = x[8*j + i]  (транспонирование 4x8)
    for (int i = 0; i < 8; ++i)
        for (int j = 0; j < 4; ++j) out[4 * i + j] = x[8 * j + i];
}

static void chi(const u8* y, u8* out) {
    u8 head[2];
    for (int k = 0; k < 2; ++k) head[k] = y[30 + k] ^ y[28 + k] ^ y[26 + k] ^ y[24 + k] ^ y[6 + k] ^ y[0 + k];
    u8 tmp[32];
    memcpy(tmp, head, 2);
    memcpy(tmp + 2, y, 30);
    memcpy(out, tmp, 32);
}

static void reverse_words(const u8* in, u8* out) {
    for (int i = 0; i < 8; ++i) memcpy(out + 4 * i, in + 4 * (7 - i), 4);
}

static void hash_step(const u8 h_in[32], const u8 m[32], u8 out[32], Gost94Sbox sbox) {
    u8 u[32], v[32], k[4][32], t1[32], t2[32];
    memcpy(u, h_in, 32); memcpy(v, m, 32);
    xor32(t1, u, v); Pperm(t1, k[0]);
    // u = A(u) ^ C2 (C2 = 0)
    A(u, t1); memcpy(u, t1, 32);
    A(v, t1); A(t1, v);
    xor32(t1, u, v); Pperm(t1, k[1]);
    A(u, t1); xor32(u, t1, C3);
    A(v, t1); A(t1, v);
    xor32(t1, u, v); Pperm(t1, k[2]);
    A(u, t1); memcpy(u, t1, 32);                // C4 = 0
    A(v, t1); A(t1, v);
    xor32(t1, u, v); Pperm(t1, k[3]);

    u8 s[32];
    for (int i = 0; i < 4; ++i) {
        // h4..h1 = h_in[0:8], [8:16], [16:24], [24:32]; шифруется ключом k4,k3,k2,k1 соответственно
        u8 key[32], blk_out[8];
        reverse_words(k[3 - i], key);
        gost28147_encrypt_block(key, h_in + 8 * i, blk_out, sbox);
        memcpy(s + 8 * i, blk_out, 8);
    }
    u8 x[32];
    memcpy(x, s, 32);
    for (int i = 0; i < 12; ++i) { chi(x, t2); memcpy(x, t2, 32); }
    xor32(t2, x, m); memcpy(x, t2, 32);
    chi(x, t2); memcpy(x, t2, 32);
    xor32(t2, h_in, x); memcpy(x, t2, 32);
    for (int i = 0; i < 61; ++i) { chi(x, t2); memcpy(x, t2, 32); }
    memcpy(out, x, 32);
}

// 256-битное сложение big-endian (по модулю 2^256)
static void add256_be(u8* acc, const u8* b) {
    unsigned carry = 0;
    for (int i = 31; i >= 0; --i) {
        unsigned t = acc[i] + b[i] + carry;
        acc[i] = (u8)t;
        carry = t >> 8;
    }
}

void gost341194(Span data, u8 out[32], Gost94Sbox sbox) {
    u8 h[32] = {0}, checksum[32] = {0};
    u64 length_bits = 0;
    size_t pos = 0;
    while (pos < data.n) {
        size_t take = data.n - pos < 32 ? data.n - pos : 32;
        u8 part[32] = {0};
        // part = data[pos:pos+take] в обратном порядке, дополненный нулями слева до 32 байт
        for (size_t i = 0; i < take; ++i) part[32 - take + i] = data.p[pos + take - 1 - i];
        length_bits += (u64)take * 8;
        add256_be(checksum, part);
        u8 nh[32];
        hash_step(h, part, nh, sbox);
        memcpy(h, nh, 32);
        pos += take;
    }
    u8 lenblk[32] = {0};
    for (int i = 0; i < 8; ++i) lenblk[31 - i] = (u8)(length_bits >> (8 * i));
    u8 nh[32];
    hash_step(h, lenblk, nh, sbox);
    memcpy(h, nh, 32);
    hash_step(h, checksum, nh, sbox);
    memcpy(out, nh, 32);
}

void gost341194_kz(Span data, u8 out[32], Gost94Sbox sbox) {
    u8 h[32];
    if (data.n == 0) {
        u8 z[32] = {0}, a[32], b[32];
        hash_step(z, z, a, sbox);
        hash_step(a, z, b, sbox);
        hash_step(b, z, h, sbox);
    } else {
        gost341194(data, h, sbox);
    }
    for (int i = 0; i < 32; ++i) out[i] = h[31 - i];
}

int gost2001_curve_by_oid(Span oid) {
    static const struct { const char* oid; int curve; } MAP[] = {
        {"1.2.398.3.10.1.1.1.1.1", CURVE_CRYPTOPRO_A}, {"1.2.398.3.10.1.1.1.1.2", CURVE_CRYPTOPRO_B},
        {"1.2.398.3.10.1.1.1.1.3", CURVE_CRYPTOPRO_C}, {"1.2.643.2.2.35.1", CURVE_CRYPTOPRO_A},
        {"1.2.643.2.2.35.2", CURVE_CRYPTOPRO_B}, {"1.2.643.2.2.35.3", CURVE_CRYPTOPRO_C},
        {"1.2.643.2.2.36.0", CURVE_CRYPTOPRO_A}, {"1.2.643.2.2.36.1", CURVE_CRYPTOPRO_C},
    };
    for (const auto& m : MAP)
        if (oid_is(oid, m.oid)) return m.curve;
    return -1;
}

}  // namespace nek
