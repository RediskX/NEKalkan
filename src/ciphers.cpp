// NEKalkan — блочные шифры (расшифрование).
#include "ciphers.h"

namespace nek {

#include "rc2_table.inc"

// ====================================== DES ======================================

static const u8 IP[64] = {58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
                          62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
                          57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
                          61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7};
static const u8 FP[64] = {40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
                          38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
                          36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
                          34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25};
static const u8 EXP[48] = {32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
                           16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1};
static const u8 PBOX[32] = {16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
                            2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25};
static const u8 PC1[56] = {57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
                           63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4};
static const u8 PC2[48] = {14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
                           41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32};
static const u8 SHIFTS[16] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};
static const u8 SBOX[8][64] = {
    {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
     4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13},
    {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
     0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9},
    {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
     13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12},
    {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
     10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14},
    {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
     4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3},
    {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
     9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13},
    {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
     1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12},
    {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
     7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}};

// Биты нумеруются с 1 слева (старший бит слова ширины width).
static u64 permute(u64 in, int in_bits, const u8* table, int out_bits) {
    u64 out = 0;
    for (int i = 0; i < out_bits; ++i) {
        out <<= 1;
        out |= (in >> (in_bits - table[i])) & 1;
    }
    return out;
}

struct DesKey { u64 k[16]; };

static void des_schedule(DesKey& ks, const u8* key8) {
    u64 key = 0;
    for (int i = 0; i < 8; ++i) key = (key << 8) | key8[i];
    u64 cd = permute(key, 64, PC1, 56);
    u32 c = (u32)(cd >> 28) & 0x0FFFFFFF, d = (u32)cd & 0x0FFFFFFF;
    for (int r = 0; r < 16; ++r) {
        for (int s = 0; s < SHIFTS[r]; ++s) {
            c = ((c << 1) | (c >> 27)) & 0x0FFFFFFF;
            d = ((d << 1) | (d >> 27)) & 0x0FFFFFFF;
        }
        ks.k[r] = permute(((u64)c << 28) | d, 56, PC2, 48);
    }
}

static u32 des_f(u32 r, u64 k) {
    u64 e = permute(r, 32, EXP, 48) ^ k;
    u32 out = 0;
    for (int i = 0; i < 8; ++i) {
        u32 six = (u32)(e >> (42 - 6 * i)) & 0x3F;
        u32 row = ((six & 0x20) >> 4) | (six & 1);
        u32 col = (six >> 1) & 0xF;
        out = (out << 4) | SBOX[i][row * 16 + col];
    }
    return (u32)permute(out, 32, PBOX, 32);
}

// decrypt=true: ключи раундов в обратном порядке
static u64 des_block(const DesKey& ks, u64 block, bool decrypt) {
    u64 ip = permute(block, 64, IP, 64);
    u32 l = (u32)(ip >> 32), r = (u32)ip;
    for (int i = 0; i < 16; ++i) {
        u64 k = ks.k[decrypt ? 15 - i : i];
        u32 t = r;
        r = l ^ des_f(r, k);
        l = t;
    }
    return permute(((u64)r << 32) | l, 64, FP, 64);
}

static u64 load64(const u8* p) { u64 v = 0; for (int i = 0; i < 8; ++i) v = (v << 8) | p[i]; return v; }
static void store64(u8* p, u64 v) { for (int i = 7; i >= 0; --i) { p[i] = (u8)v; v >>= 8; } }

bool des_cbc_decrypt(Span key, Span iv, Span in, u8* out) {
    if (key.n != 8 || iv.n != 8 || in.n % 8) return false;
    DesKey ks;
    des_schedule(ks, key.p);
    u64 prev = load64(iv.p);
    for (size_t i = 0; i < in.n; i += 8) {
        u64 c = load64(in.p + i);
        store64(out + i, des_block(ks, c, true) ^ prev);
        prev = c;
    }
    wipe(&ks, sizeof(ks));
    return true;
}

bool des3_cbc_decrypt(Span key, Span iv, Span in, u8* out) {
    if (key.n != 24 || iv.n != 8 || in.n % 8) return false;
    DesKey k1, k2, k3;
    des_schedule(k1, key.p); des_schedule(k2, key.p + 8); des_schedule(k3, key.p + 16);
    u64 prev = load64(iv.p);
    for (size_t i = 0; i < in.n; i += 8) {
        u64 c = load64(in.p + i);
        // D = D_k1(E_k2(D_k3(c)))
        u64 x = des_block(k3, c, true);
        x = des_block(k2, x, false);
        x = des_block(k1, x, true);
        store64(out + i, x ^ prev);
        prev = c;
    }
    wipe(&k1, sizeof(k1)); wipe(&k2, sizeof(k2)); wipe(&k3, sizeof(k3));
    return true;
}

// ====================================== RC2 ======================================

static inline u16 rol16(u16 x, int n) { return (u16)((x << n) | (x >> (16 - n))); }
static inline u16 ror16(u16 x, int n) { return (u16)((x >> n) | (x << (16 - n))); }

bool rc2_cbc_decrypt(Span key, int effective_bits, Span iv, Span in, u8* out) {
    if (key.n < 1 || key.n > 128 || iv.n != 8 || in.n % 8 || effective_bits < 1 || effective_bits > 1024) return false;
    // расширение ключа (RFC 2268)
    u8 L[128];
    size_t T = key.n;
    int T8 = (effective_bits + 7) / 8;
    u8 TM = (u8)(0xFF >> (8 * T8 - effective_bits));
    for (size_t i = 0; i < T; ++i) L[i] = key.p[i];
    for (size_t i = T; i < 128; ++i) L[i] = RC2_PITABLE[(u8)(L[i - 1] + L[i - T])];
    L[128 - T8] = RC2_PITABLE[L[128 - T8] & TM];
    for (int i = 127 - T8; i >= 0; --i) L[i] = RC2_PITABLE[L[i + 1] ^ L[i + T8]];
    u16 K[64];
    for (int i = 0; i < 64; ++i) K[i] = (u16)(L[2 * i] | (L[2 * i + 1] << 8));

    u8 prev[8];
    memcpy(prev, iv.p, 8);
    for (size_t off = 0; off < in.n; off += 8) {
        u16 R[4];
        for (int i = 0; i < 4; ++i) R[i] = (u16)(in.p[off + 2 * i] | (in.p[off + 2 * i + 1] << 8));
        static const int S[4] = {1, 2, 3, 5};
        int j = 63;
        auto r_mash = [&](int i) {
            R[i] = (u16)(R[i] - K[R[(i + 3) & 3] & 63]);
        };
        for (int round = 0; round < 16; ++round) {
            for (int i = 3; i >= 0; --i) {
                R[i] = ror16(R[i], S[i]);
                R[i] = (u16)(R[i] - (K[j--] + (R[(i + 3) & 3] & R[(i + 2) & 3]) + (~R[(i + 3) & 3] & R[(i + 1) & 3])));
            }
            if (round == 4 || round == 10) {
                for (int i = 3; i >= 0; --i) r_mash(i);
            }
        }
        u8 plain[8];
        for (int i = 0; i < 4; ++i) { plain[2 * i] = (u8)R[i]; plain[2 * i + 1] = (u8)(R[i] >> 8); }
        for (int i = 0; i < 8; ++i) out[off + i] = plain[i] ^ prev[i];
        memcpy(prev, in.p + off, 8);
    }
    (void)rol16;
    wipe(L, sizeof(L)); wipe(K, sizeof(K));
    return true;
}

// ====================================== AES ======================================

static u8 g_sbox[256], g_inv_sbox[256];
static int g_aes_ready;

static u8 gmul(u8 a, u8 b) {
    u8 p = 0;
    for (int i = 0; i < 8; ++i) {
        if (b & 1) p ^= a;
        u8 hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

static void aes_init() {
    if (__atomic_load_n(&g_aes_ready, __ATOMIC_ACQUIRE)) return;
    // S-блок: обратный элемент в GF(2^8) + аффинное преобразование
    u8 sb[256], inv[256];
    for (int a = 0; a < 256; ++a) {
        u8 r = 0;
        if (a) { for (int b = 1; b < 256; ++b) if (gmul((u8)a, (u8)b) == 1) { r = (u8)b; break; } }
        u8 x = r, y = r;
        for (int i = 0; i < 4; ++i) { y = (u8)((y << 1) | (y >> 7)); x ^= y; }
        sb[a] = x ^ 0x63;
    }
    for (int i = 0; i < 256; ++i) inv[sb[i]] = (u8)i;
    for (int i = 0; i < 256; ++i) { g_sbox[i] = sb[i]; g_inv_sbox[i] = inv[i]; }
    __atomic_store_n(&g_aes_ready, 1, __ATOMIC_RELEASE);
}

bool aes_cbc_decrypt(Span key, Span iv, Span in, u8* out) {
    if ((key.n != 16 && key.n != 24 && key.n != 32) || iv.n != 16 || in.n % 16) return false;
    aes_init();
    int nk = (int)key.n / 4, nr = nk + 6;
    u8 w[240];
    memcpy(w, key.p, key.n);
    u8 rcon = 1;
    for (int i = nk; i < 4 * (nr + 1); ++i) {
        u8 t[4];
        memcpy(t, w + 4 * (i - 1), 4);
        if (i % nk == 0) {
            u8 tmp = t[0];
            t[0] = g_sbox[t[1]] ^ rcon; t[1] = g_sbox[t[2]]; t[2] = g_sbox[t[3]]; t[3] = g_sbox[tmp];
            rcon = gmul(rcon, 2);
        } else if (nk > 6 && i % nk == 4) {
            for (int k = 0; k < 4; ++k) t[k] = g_sbox[t[k]];
        }
        for (int k = 0; k < 4; ++k) w[4 * i + k] = w[4 * (i - nk) + k] ^ t[k];
    }
    u8 prev[16];
    memcpy(prev, iv.p, 16);
    for (size_t off = 0; off < in.n; off += 16) {
        u8 s[16];
        memcpy(s, in.p + off, 16);
        for (int k = 0; k < 16; ++k) s[k] ^= w[16 * nr + k];
        for (int round = nr - 1; round >= 0; --round) {
            // InvShiftRows
            u8 t[16];
            for (int c = 0; c < 4; ++c)
                for (int r = 0; r < 4; ++r) t[4 * ((c + r) & 3) + r] = s[4 * c + r];
            for (int k = 0; k < 16; ++k) s[k] = g_inv_sbox[t[k]] ^ w[16 * round + k];
            if (round > 0) {
                for (int c = 0; c < 4; ++c) {
                    u8 a0 = s[4 * c], a1 = s[4 * c + 1], a2 = s[4 * c + 2], a3 = s[4 * c + 3];
                    s[4 * c]     = gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9);
                    s[4 * c + 1] = gmul(a0, 9) ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13);
                    s[4 * c + 2] = gmul(a0, 13) ^ gmul(a1, 9) ^ gmul(a2, 14) ^ gmul(a3, 11);
                    s[4 * c + 3] = gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9) ^ gmul(a3, 14);
                }
            }
        }
        for (int k = 0; k < 16; ++k) out[off + k] = s[k] ^ prev[k];
        memcpy(prev, in.p + off, 16);
    }
    wipe(w, sizeof(w));
    return true;
}

bool pkcs7_unpad(Bytes& b, size_t block) {
    if (b.n == 0 || b.n % block) return false;
    u8 pad = b.p[b.n - 1];
    if (pad < 1 || pad > block || pad > b.n) return false;
    for (size_t i = 0; i < pad; ++i)
        if (b.p[b.n - 1 - i] != pad) return false;
    b.n -= pad;
    b.p[b.n] = 0;
    return true;
}

}  // namespace nek
