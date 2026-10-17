// NEKalkan — ГОСТ Р 34.10-2012.
#include "gost3410.h"
#include "bignum.h"
#include "plat.h"

namespace nek {

#include "gost_curves.inc"

static const int FN = 8;   // слов в элементе поля (до 512 бит)

struct GostCurve {
    int size;
    int n;                 // слов
    Mont fp, fq;
    u64 a[FN], b[FN];      // в форме Монтгомери по p
    u64 gx[FN], gy[FN];    // базовая точка, форма Монтгомери по p
    int qbits;
};

struct JPoint { u64 x[FN], y[FN], z[FN]; };

static const int CURVE_COUNT = 5;
static GostCurve g_curves[CURVE_COUNT];
static int g_curve_state[CURVE_COUNT];     // 0 — не готова, 1 — идёт инициализация, 2 — готова

static bool curve_build(GostCurve& c, const CurveDef& d) {
    c.size = d.size;
    c.n = d.size / 8;
    u64 t[FN];
    bn_from_be(t, c.n, d.p, d.size);
    if (!mont_init(c.fp, t, c.n)) return false;
    bn_from_be(t, c.n, d.q, d.size);
    if (!mont_init(c.fq, t, c.n)) return false;
    c.qbits = bn_bitlen(c.fq.m, c.n);
    bn_zero(c.a, FN); bn_zero(c.b, FN); bn_zero(c.gx, FN); bn_zero(c.gy, FN);
    bn_from_be(t, c.n, d.a, d.size); to_mont(c.fp, c.a, t);
    bn_from_be(t, c.n, d.b, d.size); to_mont(c.fp, c.b, t);
    bn_from_be(t, c.n, d.x, d.size); to_mont(c.fp, c.gx, t);
    bn_from_be(t, c.n, d.y, d.size); to_mont(c.fp, c.gy, t);
    return true;
}

const GostCurve* gost_curve_id(int idx) {
    if (idx < 0 || idx >= CURVE_COUNT) return 0;
    for (;;) {
        int st = __atomic_load_n(&g_curve_state[idx], __ATOMIC_ACQUIRE);
        if (st == 2) return &g_curves[idx];
        int expected = 0;
        if (st == 0 && __atomic_compare_exchange_n(&g_curve_state[idx], &expected, 1, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
            bool ok = curve_build(g_curves[idx], CURVE_DEFS[idx]);
            __atomic_store_n(&g_curve_state[idx], ok ? 2 : 0, __ATOMIC_RELEASE);
            return ok ? &g_curves[idx] : 0;
        }
        __builtin_ia32_pause();                 // другой поток строит кривую — подождать
    }
}

const GostCurve* gost_curve(int size) { return size == 32 ? gost_curve_id(CURVE_TC26_256_A) : (size == 64 ? gost_curve_id(CURVE_TC26_512_A) : 0); }

int gost_curve_size(const GostCurve* c) { return c->size; }

// ---- арифметика точек (якобиановы координаты, форма Монтгомери) ---------------

static inline void fmul(const GostCurve& c, u64* r, const u64* a, const u64* b) { mont_mul(c.fp, r, a, b); }
static inline void fsqr(const GostCurve& c, u64* r, const u64* a) { mont_sqr(c.fp, r, a); }
static inline void fadd(const GostCurve& c, u64* r, const u64* a, const u64* b) { mont_add(c.fp, r, a, b); }
static inline void fsub(const GostCurve& c, u64* r, const u64* a, const u64* b) { mont_sub(c.fp, r, a, b); }

static inline bool is_inf(const GostCurve& c, const JPoint& p) { return bn_is_zero(p.z, c.n); }

static void set_inf(const GostCurve& c, JPoint& p) {
    bn_zero(p.x, FN); bn_zero(p.y, FN); bn_zero(p.z, FN);
    bn_copy(p.x, c.fp.one, c.n);
    bn_copy(p.y, c.fp.one, c.n);
}

static void pt_dbl(const GostCurve& c, JPoint& r, const JPoint& p) {
    u64 xx[FN] = {0}, yy[FN] = {0}, yyyy[FN] = {0}, zz[FN] = {0}, s[FN] = {0}, m[FN] = {0}, t[FN] = {0}, u[FN] = {0};
    fsqr(c, xx, p.x);
    fsqr(c, yy, p.y);
    fsqr(c, yyyy, yy);
    fsqr(c, zz, p.z);
    fadd(c, u, p.x, yy); fsqr(c, u, u); fsub(c, u, u, xx); fsub(c, u, u, yyyy);
    fadd(c, s, u, u);                                   // S = 2((X+YY)^2-XX-YYYY)
    fsqr(c, t, zz); fmul(c, t, t, c.a);                 // a*ZZ^2
    fadd(c, m, xx, xx); fadd(c, m, m, xx); fadd(c, m, m, t);   // M = 3XX + a ZZ^2
    u64 nx[FN] = {0}, ny[FN] = {0}, nz[FN] = {0};
    fsqr(c, nx, m); fsub(c, nx, nx, s); fsub(c, nx, nx, s);    // T = M^2 - 2S
    fsub(c, t, s, nx); fmul(c, ny, m, t);
    fadd(c, u, yyyy, yyyy); fadd(c, u, u, u); fadd(c, u, u, u);  // 8 YYYY
    fsub(c, ny, ny, u);
    fadd(c, nz, p.y, p.z); fsqr(c, nz, nz); fsub(c, nz, nz, yy); fsub(c, nz, nz, zz);
    bn_copy(r.x, nx, FN); bn_copy(r.y, ny, FN); bn_copy(r.z, nz, FN);
}

static void pt_add(const GostCurve& c, JPoint& r, const JPoint& p1, const JPoint& p2) {
    if (is_inf(c, p1)) { r = p2; return; }
    if (is_inf(c, p2)) { r = p1; return; }
    u64 z1z1[FN] = {0}, z2z2[FN] = {0}, u1[FN] = {0}, u2[FN] = {0}, s1[FN] = {0}, s2[FN] = {0}, h[FN] = {0}, i[FN] = {0}, j[FN] = {0}, rr[FN] = {0}, v[FN] = {0}, t[FN] = {0};
    fsqr(c, z1z1, p1.z);
    fsqr(c, z2z2, p2.z);
    fmul(c, u1, p1.x, z2z2);
    fmul(c, u2, p2.x, z1z1);
    fmul(c, s1, p1.y, p2.z); fmul(c, s1, s1, z2z2);
    fmul(c, s2, p2.y, p1.z); fmul(c, s2, s2, z1z1);
    fsub(c, h, u2, u1);
    fsub(c, rr, s2, s1);
    if (bn_is_zero(h, c.n)) {
        if (bn_is_zero(rr, c.n)) { pt_dbl(c, r, p1); return; }
        set_inf(c, r);
        return;
    }
    fadd(c, rr, rr, rr);                                // r = 2(S2-S1)
    fadd(c, i, h, h); fsqr(c, i, i);                    // I = (2H)^2
    fmul(c, j, h, i);                                   // J = H*I
    fmul(c, v, u1, i);                                  // V = U1*I
    u64 nx[FN] = {0}, ny[FN] = {0}, nz[FN] = {0};
    fsqr(c, nx, rr); fsub(c, nx, nx, j); fsub(c, nx, nx, v); fsub(c, nx, nx, v);
    fsub(c, t, v, nx); fmul(c, ny, rr, t);
    fmul(c, t, s1, j); fadd(c, t, t, t);
    fsub(c, ny, ny, t);
    fadd(c, nz, p1.z, p2.z); fsqr(c, nz, nz); fsub(c, nz, nz, z1z1); fsub(c, nz, nz, z2z2);
    fmul(c, nz, nz, h);
    bn_copy(r.x, nx, FN); bn_copy(r.y, ny, FN); bn_copy(r.z, nz, FN);
}

static void pt_from_affine(const GostCurve& c, JPoint& r, const u64* x, const u64* y) {
    bn_zero(r.x, FN); bn_zero(r.y, FN); bn_zero(r.z, FN);
    bn_copy(r.x, x, c.n); bn_copy(r.y, y, c.n); bn_copy(r.z, c.fp.one, c.n);
}

// В аффинные координаты (в форме Монтгомери). false — бесконечность.
static bool pt_to_affine(const GostCurve& c, const JPoint& p, u64* x, u64* y) {
    if (is_inf(c, p)) return false;
    u64 zi[FN] = {0}, z2[FN] = {0}, z3[FN] = {0};
    mont_inv_prime(c.fp, zi, p.z);
    fsqr(c, z2, zi);
    fmul(c, z3, z2, zi);
    fmul(c, x, p.x, z2);
    fmul(c, y, p.y, z3);
    return true;
}

// y^2 = x^3 + a x + b ?
static bool on_curve(const GostCurve& c, const u64* x, const u64* y) {
    u64 l[FN], r[FN];
    fsqr(c, l, y);
    fsqr(c, r, x); fadd(c, r, r, c.a); fmul(c, r, r, x); fadd(c, r, r, c.b);
    return bn_cmp(l, r, c.n) == 0;
}

// R = k*P, k — обычное число (c.n слов)
static void pt_mul(const GostCurve& c, JPoint& r, const u64* k, const JPoint& p) {
    JPoint acc;
    set_inf(c, acc);
    int bits = bn_bitlen(k, c.n);
    for (int i = bits - 1; i >= 0; --i) {
        pt_dbl(c, acc, acc);
        if (bn_bit(k, i)) pt_add(c, acc, acc, p);
    }
    r = acc;
}

// R = k1*P1 + k2*P2 (приём Шамира)
static void pt_mul2(const GostCurve& c, JPoint& r, const u64* k1, const JPoint& p1, const u64* k2, const JPoint& p2) {
    JPoint sum;
    pt_add(c, sum, p1, p2);
    JPoint acc;
    set_inf(c, acc);
    int b1 = bn_bitlen(k1, c.n), b2 = bn_bitlen(k2, c.n);
    int bits = b1 > b2 ? b1 : b2;
    for (int i = bits - 1; i >= 0; --i) {
        pt_dbl(c, acc, acc);
        bool a = bn_bit(k1, i), b = bn_bit(k2, i);
        if (a && b) pt_add(c, acc, acc, sum);
        else if (a) pt_add(c, acc, acc, p1);
        else if (b) pt_add(c, acc, acc, p2);
    }
    r = acc;
}

// ---- вспомогательные: число e из дайджеста, скаляры по модулю q ---------------

// e = little-endian чтение дайджеста, приведённое по модулю q; 0 → 1.
static bool digest_to_e(const GostCurve& c, Span digest, u64* e) {
    if (digest.n != (size_t)c.size) return false;
    u64 raw[FN];
    bn_from_le(raw, c.n, digest.p, digest.n);
    bn_mod(e, raw, c.n, c.fq.m, c.n);
    if (bn_is_zero(e, c.n)) { bn_zero(e, c.n); e[0] = 1; }
    return true;
}

bool gost3410_verify(const GostCurve* c, Span pub_xy_le, Span digest, Span sig_rs_le) {
    if (!c) return false;
    int sz = c->size, n = c->n;
    if (pub_xy_le.n != 2 * (size_t)sz || sig_rs_le.n != 2 * (size_t)sz) return false;
    u64 r[FN], s[FN], e[FN];
    bn_from_le(r, n, sig_rs_le.p, sz);
    bn_from_le(s, n, sig_rs_le.p + sz, sz);
    if (bn_is_zero(r, n) || bn_is_zero(s, n)) return false;
    if (bn_cmp(r, c->fq.m, n) >= 0 || bn_cmp(s, c->fq.m, n) >= 0) return false;
    if (!digest_to_e(*c, digest, e)) return false;

    u64 qx[FN], qy[FN], qxm[FN], qym[FN];
    bn_from_le(qx, n, pub_xy_le.p, sz);
    bn_from_le(qy, n, pub_xy_le.p + sz, sz);
    if (bn_cmp(qx, c->fp.m, n) >= 0 || bn_cmp(qy, c->fp.m, n) >= 0) return false;
    to_mont(c->fp, qxm, qx);
    to_mont(c->fp, qym, qy);
    if (!on_curve(*c, qxm, qym)) return false;
    {
        // открытый ключ обязан лежать в подгруппе порядка q (у кривых с кофактором ≠ 1 одной проверки уравнения мало)
        JPoint qj, qq;
        pt_from_affine(*c, qj, qxm, qym);
        pt_mul(*c, qq, c->fq.m, qj);
        if (!is_inf(*c, qq)) return false;
    }

    // v = e^-1, z1 = s*v, z2 = -r*v (mod q)
    u64 em[FN], vm[FN], sm[FN], rm[FN], z1m[FN], z2m[FN], z1[FN], z2[FN];
    to_mont(c->fq, em, e);
    mont_inv_prime(c->fq, vm, em);
    to_mont(c->fq, sm, s);
    to_mont(c->fq, rm, r);
    mont_mul(c->fq, z1m, sm, vm);
    mont_mul(c->fq, z2m, rm, vm);
    mont_neg(c->fq, z2m, z2m);
    from_mont(c->fq, z1, z1m);
    from_mont(c->fq, z2, z2m);

    JPoint g, q, res;
    pt_from_affine(*c, g, c->gx, c->gy);
    pt_from_affine(*c, q, qxm, qym);
    pt_mul2(*c, res, z1, g, z2, q);
    u64 ax[FN], ay[FN];
    if (!pt_to_affine(*c, res, ax, ay)) return false;
    u64 xr[FN], xmod[FN];
    from_mont(c->fp, xr, ax);
    bn_mod(xmod, xr, n, c->fq.m, n);
    return bn_cmp(xmod, r, n) == 0;
}

static bool sign_with_k(const GostCurve* c, Span priv_be, Span digest, const u64* k, u8* sig_out) {
    int sz = c->size, n = c->n;
    if (priv_be.n != (size_t)sz) return false;
    u64 d[FN], e[FN];
    bn_from_be(d, n, priv_be.p, sz);
    if (bn_is_zero(d, n) || bn_cmp(d, c->fq.m, n) >= 0) return false;
    if (!digest_to_e(*c, digest, e)) return false;
    if (bn_is_zero(k, n) || bn_cmp(k, c->fq.m, n) >= 0) return false;

    JPoint g, kg;
    pt_from_affine(*c, g, c->gx, c->gy);
    pt_mul(*c, kg, k, g);
    u64 ax[FN], ay[FN];
    if (!pt_to_affine(*c, kg, ax, ay)) return false;
    u64 xr[FN], r[FN];
    from_mont(c->fp, xr, ax);
    bn_mod(r, xr, n, c->fq.m, n);
    if (bn_is_zero(r, n)) return false;
    // s = r*d + k*e mod q
    u64 rm[FN], dm[FN], km[FN], em[FN], t1[FN], t2[FN], sm[FN], s[FN];
    to_mont(c->fq, rm, r); to_mont(c->fq, dm, d); to_mont(c->fq, km, k); to_mont(c->fq, em, e);
    mont_mul(c->fq, t1, rm, dm);
    mont_mul(c->fq, t2, km, em);
    mont_add(c->fq, sm, t1, t2);
    from_mont(c->fq, s, sm);
    wipe(d, sizeof(d)); wipe(dm, sizeof(dm)); wipe(km, sizeof(km));
    if (bn_is_zero(s, n)) return false;
    bn_to_le(sig_out, sz, r, n);
    bn_to_le(sig_out + sz, sz, s, n);
    return true;
}

bool gost3410_sign_k(const GostCurve* c, Span priv_be, Span digest, Span k_be, u8* sig_rs_le) {
    if (!c || k_be.n != (size_t)c->size) return false;
    u64 k[FN];
    bn_from_be(k, c->n, k_be.p, k_be.n);
    return sign_with_k(c, priv_be, digest, k, sig_rs_le);
}

bool gost3410_sign(const GostCurve* c, Span priv_be, Span digest, u8* sig_rs_le) {
    if (!c) return false;
    int sz = c->size, n = c->n;
    for (int attempt = 0; attempt < 100; ++attempt) {
        u8 kb[64];
        if (!plat_random(kb, sz)) return false;
        // привести к длине q: срезать лишние старшие биты
        int extra = sz * 8 - c->qbits;
        if (extra > 0) kb[0] &= (u8)(0xFF >> extra);
        u64 k[FN];
        bn_from_be(k, n, kb, sz);
        wipe(kb, sizeof(kb));
        if (bn_is_zero(k, n) || bn_cmp(k, c->fq.m, n) >= 0) continue;
        bool ok = sign_with_k(c, priv_be, digest, k, sig_rs_le);
        wipe(k, sizeof(k));
        if (ok) return true;
    }
    return false;
}

bool gost3410_public_be(const GostCurve* c, Span priv_be, u8* xy_be) {
    if (!c || priv_be.n != (size_t)c->size) return false;
    int sz = c->size, n = c->n;
    u64 d[FN];
    bn_from_be(d, n, priv_be.p, sz);
    if (bn_is_zero(d, n) || bn_cmp(d, c->fq.m, n) >= 0) return false;
    JPoint g, q;
    pt_from_affine(*c, g, c->gx, c->gy);
    pt_mul(*c, q, d, g);
    wipe(d, sizeof(d));
    u64 ax[FN], ay[FN], x[FN], y[FN];
    if (!pt_to_affine(*c, q, ax, ay)) return false;
    from_mont(c->fp, x, ax);
    from_mont(c->fp, y, ay);
    bn_to_be(xy_be, sz, x, n);
    bn_to_be(xy_be + sz, sz, y, n);
    return true;
}

}  // namespace nek
