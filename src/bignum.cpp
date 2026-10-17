// NEKalkan — длинная арифметика.
#include "bignum.h"

namespace nek {

typedef unsigned __int128 u128;

void bn_zero(u64* r, int n) { for (int i = 0; i < n; ++i) r[i] = 0; }
void bn_copy(u64* r, const u64* a, int n) { for (int i = 0; i < n; ++i) r[i] = a[i]; }

bool bn_is_zero(const u64* a, int n) {
    u64 acc = 0;
    for (int i = 0; i < n; ++i) acc |= a[i];
    return acc == 0;
}

int bn_cmp(const u64* a, const u64* b, int n) {
    for (int i = n - 1; i >= 0; --i) {
        if (a[i] > b[i]) return 1;
        if (a[i] < b[i]) return -1;
    }
    return 0;
}

u64 bn_add(u64* r, const u64* a, const u64* b, int n) {
    u64 carry = 0;
    for (int i = 0; i < n; ++i) {
        u128 s = (u128)a[i] + b[i] + carry;
        r[i] = (u64)s;
        carry = (u64)(s >> 64);
    }
    return carry;
}

u64 bn_sub(u64* r, const u64* a, const u64* b, int n) {
    u64 borrow = 0;
    for (int i = 0; i < n; ++i) {
        u128 d = (u128)a[i] - b[i] - borrow;
        r[i] = (u64)d;
        borrow = (u64)(d >> 64) & 1;
    }
    return borrow;
}

int bn_bitlen(const u64* a, int n) {
    for (int i = n - 1; i >= 0; --i) {
        if (a[i]) {
            int b = 63;
            while (!((a[i] >> b) & 1)) --b;
            return i * 64 + b + 1;
        }
    }
    return 0;
}

bool bn_bit(const u64* a, int i) { return (a[i >> 6] >> (i & 63)) & 1; }

void bn_from_be(u64* r, int n, const u8* be, size_t len) {
    bn_zero(r, n);
    for (size_t i = 0; i < len; ++i) {
        size_t pos = len - 1 - i;                    // номер байта с младшего конца
        if ((pos >> 3) >= (size_t)n) continue;          // слишком длинный вход — старшее отбрасываем
        r[pos >> 3] |= (u64)be[i] << (8 * (pos & 7));
    }
}

void bn_to_be(u8* be, size_t len, const u64* a, int n) {
    for (size_t i = 0; i < len; ++i) {
        size_t pos = len - 1 - i;
        be[i] = (pos >> 3) < (size_t)n ? (u8)(a[pos >> 3] >> (8 * (pos & 7))) : 0;
    }
}

void bn_from_le(u64* r, int n, const u8* le, size_t len) {
    bn_zero(r, n);
    for (size_t i = 0; i < len; ++i) {
        if ((i >> 3) >= (size_t)n) break;
        r[i >> 3] |= (u64)le[i] << (8 * (i & 7));
    }
}

void bn_to_le(u8* le, size_t len, const u64* a, int n) {
    for (size_t i = 0; i < len; ++i) le[i] = (i >> 3) < (size_t)n ? (u8)(a[i >> 3] >> (8 * (i & 7))) : 0;
}

void bn_mul_full(u64* r, const u64* a, int na, const u64* b, int nb) {
    for (int i = 0; i < na + nb; ++i) r[i] = 0;
    for (int i = 0; i < na; ++i) {
        u64 carry = 0;
        for (int j = 0; j < nb; ++j) {
            u128 t = (u128)a[i] * b[j] + r[i + j] + carry;
            r[i + j] = (u64)t;
            carry = (u64)(t >> 64);
        }
        r[i + nb] = carry;
    }
}

void bn_mod(u64* r, const u64* a, int na, const u64* m, int nm) {
    // остаток накапливается в nm+1 словах (после сдвига может временно превысить m)
    u64 rem[BN_MAX + 1];
    for (int i = 0; i <= nm; ++i) rem[i] = 0;
    u64 mm[BN_MAX + 1];
    for (int i = 0; i < nm; ++i) mm[i] = m[i];
    mm[nm] = 0;
    for (int bit = na * 64 - 1; bit >= 0; --bit) {
        // rem = rem*2 + bit
        u64 carry = (a[bit >> 6] >> (bit & 63)) & 1;
        for (int i = 0; i <= nm; ++i) {
            u64 nc = rem[i] >> 63;
            rem[i] = (rem[i] << 1) | carry;
            carry = nc;
        }
        if (bn_cmp(rem, mm, nm + 1) >= 0) bn_sub(rem, rem, mm, nm + 1);
    }
    for (int i = 0; i < nm; ++i) r[i] = rem[i];
    wipe(rem, sizeof(rem));
}

// ---- Монтгомери -----------------------------------------------------------------

// r = (a + b) mod m, a,b < m
void mont_add(const Mont& c, u64* r, const u64* a, const u64* b) {
    u64 t[BN_MAX];
    u64 carry = bn_add(t, a, b, c.n);
    u64 s[BN_MAX];
    u64 borrow = bn_sub(s, t, c.m, c.n);
    // если было переполнение, либо t >= m — берём t - m
    bool use_s = carry || !borrow;
    for (int i = 0; i < c.n; ++i) r[i] = use_s ? s[i] : t[i];
}

void mont_sub(const Mont& c, u64* r, const u64* a, const u64* b) {
    u64 t[BN_MAX];
    u64 borrow = bn_sub(t, a, b, c.n);
    if (borrow) bn_add(t, t, c.m, c.n);
    for (int i = 0; i < c.n; ++i) r[i] = t[i];
}

void mont_neg(const Mont& c, u64* r, const u64* a) {
    if (bn_is_zero(a, c.n)) { bn_zero(r, c.n); return; }
    bn_sub(r, c.m, a, c.n);
}

void mont_mul(const Mont& c, u64* r, const u64* a, const u64* b) {
    const int n = c.n;
    u64 t[BN_MAX + 2];
    for (int i = 0; i < n + 2; ++i) t[i] = 0;
    for (int i = 0; i < n; ++i) {
        u64 carry = 0;
        for (int j = 0; j < n; ++j) {
            u128 s = (u128)a[j] * b[i] + t[j] + carry;
            t[j] = (u64)s;
            carry = (u64)(s >> 64);
        }
        u128 s = (u128)t[n] + carry;
        t[n] = (u64)s;
        t[n + 1] = (u64)(s >> 64);
        u64 mi = t[0] * c.m0inv;
        u128 s0 = (u128)c.m[0] * mi + t[0];
        carry = (u64)(s0 >> 64);
        for (int j = 1; j < n; ++j) {
            u128 sj = (u128)c.m[j] * mi + t[j] + carry;
            t[j - 1] = (u64)sj;
            carry = (u64)(sj >> 64);
        }
        u128 sn = (u128)t[n] + carry;
        t[n - 1] = (u64)sn;
        t[n] = t[n + 1] + (u64)(sn >> 64);
        t[n + 1] = 0;
    }
    // t < 2m; вычесть m при необходимости
    u64 s[BN_MAX];
    u64 borrow = bn_sub(s, t, c.m, n);
    bool use_s = t[n] || !borrow;
    for (int i = 0; i < n; ++i) r[i] = use_s ? s[i] : t[i];
}

void mont_sqr(const Mont& c, u64* r, const u64* a) { mont_mul(c, r, a, a); }

bool mont_init(Mont& c, const u64* m, int n) {
    if (n < 1 || n > BN_MAX || !(m[0] & 1) || m[n - 1] == 0) return false;
    if (n == 1 && m[0] < 3) return false;          // модуль 1 (и 0) не допускается
    c.n = n;
    for (int i = 0; i < n; ++i) c.m[i] = m[i];
    // m0inv: Ньютон для обратного по модулю 2^64
    u64 inv = 1;
    for (int i = 0; i < 6; ++i) inv *= 2 - m[0] * inv;
    c.m0inv = (u64)0 - inv;
    // R mod m: 1, удвоить 64n раз; затем ещё 64n раз → R^2 mod m
    u64 x[BN_MAX];
    bn_zero(x, n);
    x[0] = 1;
    // 1 < m (m ≥ 3 нечётное), делаем reduce на случай m = 1 нет — исключено проверкой выше
    for (int pass = 0; pass < 2; ++pass) {
        for (int i = 0; i < 64 * n; ++i) {
            u64 carry = 0;
            for (int j = 0; j < n; ++j) {
                u64 nc = x[j] >> 63;
                x[j] = (x[j] << 1) | carry;
                carry = nc;
            }
            u64 s[BN_MAX];
            u64 borrow = bn_sub(s, x, m, n);
            if (carry || !borrow) bn_copy(x, s, n);
        }
        if (pass == 0) bn_copy(c.one, x, n);
        else bn_copy(c.rr, x, n);
    }
    return true;
}

void to_mont(const Mont& c, u64* r, const u64* a) { mont_mul(c, r, a, c.rr); }

void from_mont(const Mont& c, u64* r, const u64* a) {
    u64 one[BN_MAX];
    bn_zero(one, c.n);
    one[0] = 1;
    mont_mul(c, r, a, one);
}

void mont_pow(const Mont& c, u64* r, const u64* a, const u64* e, int ne) {
    u64 acc[BN_MAX];
    bn_copy(acc, c.one, c.n);
    int bits = bn_bitlen(e, ne);
    for (int i = bits - 1; i >= 0; --i) {
        mont_sqr(c, acc, acc);
        if (bn_bit(e, i)) mont_mul(c, acc, acc, a);
    }
    bn_copy(r, acc, c.n);
}

void mont_inv_prime(const Mont& c, u64* r, const u64* a) {
    u64 e[BN_MAX];
    bn_copy(e, c.m, c.n);
    // e = m - 2 (m нечётное и ≥ 3, поэтому младшее слово ≥ 1 и заёма не будет, если m[0] ≥ 2)
    u64 two[BN_MAX];
    bn_zero(two, c.n);
    two[0] = 2;
    bn_sub(e, e, two, c.n);
    mont_pow(c, r, a, e, c.n);
}

}  // namespace nek
