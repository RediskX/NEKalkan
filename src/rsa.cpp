// NEKalkan — RSA PKCS#1 v1.5.
#include "rsa.h"
#include "bignum.h"

namespace nek {

static const u8 DI_SHA1[] = {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14};
static const u8 DI_SHA256[] = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
static const u8 DI_SHA384[] = {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30};
static const u8 DI_SHA512[] = {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40};

Span rsa_digest_info_prefix(HashAlg alg) {
    switch (alg) {
        case H_SHA1: return Span(DI_SHA1, sizeof(DI_SHA1));
        case H_SHA256: return Span(DI_SHA256, sizeof(DI_SHA256));
        case H_SHA384: return Span(DI_SHA384, sizeof(DI_SHA384));
        case H_SHA512: return Span(DI_SHA512, sizeof(DI_SHA512));
        default: return Span();
    }
}

// EM = 00 01 FF..FF 00 DigestInfo
static bool build_em(Bytes& em, size_t k, HashAlg alg, Span digest) {
    Span pre = rsa_digest_info_prefix(alg);
    if (!pre.n || digest.n != hash_size(alg)) return false;
    size_t tlen = pre.n + digest.n;
    if (k < tlen + 11) return false;
    if (!em.resize(k)) return false;
    em[0] = 0x00; em[1] = 0x01;
    for (size_t i = 2; i < k - tlen - 1; ++i) em[i] = 0xFF;
    em[k - tlen - 1] = 0x00;
    memcpy(em.p + k - tlen, pre.p, pre.n);
    memcpy(em.p + k - digest.n, digest.p, digest.n);
    return true;
}

static Span strip_zeros(Span s) {
    while (s.n > 1 && s.p[0] == 0) { s.p++; s.n--; }
    return s;
}

static int limbs_for(size_t bytes) { return (int)((bytes + 7) / 8); }

bool rsa_pkcs1_verify(Span n_be, Span e_be, HashAlg alg, Span digest, Span sig) {
    n_be = strip_zeros(n_be);
    e_be = strip_zeros(e_be);
    size_t k = n_be.n;
    if (k < 64 || k > (size_t)BN_MAX * 8 - 8 || (n_be.p[0] == 0) || (n_be.p[k - 1] & 1) == 0) return false;
    if (e_be.n == 0 || e_be.n > k) return false;
    if (sig.n != k) return false;
    int nl = limbs_for(k);
    u64 n[BN_MAX], s[BN_MAX], e[BN_MAX];
    bn_from_be(n, nl, n_be.p, k);
    bn_from_be(s, nl, sig.p, k);
    bn_from_be(e, nl, e_be.p, e_be.n);
    if (bn_cmp(s, n, nl) >= 0) return false;
    if (bn_is_zero(e, nl) || (e[0] & 1) == 0) return false;
    {
        // RFC 8017 §3.1: 3 ≤ e < n (e = 1 превращает проверку в «предъявите блок EM»)
        bool big = false;
        for (int i = 1; i < nl; ++i) if (e[i]) big = true;
        if (!big && e[0] < 3) return false;
        if (bn_cmp(e, n, nl) >= 0) return false;
    }
    Mont* c = (Mont*)xalloc(sizeof(Mont));
    if (!c) return false;
    bool ok = false;
    if (mont_init(*c, n, nl)) {
        u64 sm[BN_MAX], rm[BN_MAX], r[BN_MAX];
        to_mont(*c, sm, s);
        mont_pow(*c, rm, sm, e, nl);
        from_mont(*c, r, rm);
        u8 got[BN_MAX * 8];
        bn_to_be(got, k, r, nl);
        Bytes em;
        if (build_em(em, k, alg, digest)) ok = ct_eq(got, em.p, k);
    }
    xfree(c);
    return ok;
}

bool rsa_pkcs1_sign(const RsaPrivKey& key, HashAlg alg, Span digest, Bytes& sig) {
    Span n_be = strip_zeros(key.n.span()), p_be = strip_zeros(key.p.span()), q_be = strip_zeros(key.q.span());
    Span dp_be = strip_zeros(key.dp.span()), dq_be = strip_zeros(key.dq.span()), qi_be = strip_zeros(key.qinv.span());
    Span e_be = strip_zeros(key.e.span());
    size_t k = n_be.n;
    if (k < 64 || k > (size_t)BN_MAX * 8 - 8 || p_be.n == 0 || q_be.n == 0) return false;
    // все компоненты ключа не длиннее модуля, а p и q вместе укладываются в буферы (CRT: p*q < 2^(8k+16))
    if (p_be.n > k || q_be.n > k || dp_be.n > k || dq_be.n > k || qi_be.n > k || e_be.n > k || p_be.n + q_be.n > k + 2) return false;
    Bytes em;
    if (!build_em(em, k, alg, digest)) return false;

    int nl = limbs_for(k), pl = limbs_for(p_be.n), ql = limbs_for(q_be.n);
    int hl = pl > ql ? pl : ql;
    u64 c[BN_MAX], pp[BN_MAX], qq[BN_MAX], dp[BN_MAX], dq[BN_MAX], qi[BN_MAX];
    bn_from_be(c, nl, em.p, k);
    bn_from_be(pp, pl, p_be.p, p_be.n);
    bn_from_be(qq, ql, q_be.p, q_be.n);
    bn_from_be(dp, pl, dp_be.p, dp_be.n);
    bn_from_be(dq, ql, dq_be.p, dq_be.n);
    bn_from_be(qi, pl, qi_be.p, qi_be.n);

    Mont* mp = (Mont*)xalloc(sizeof(Mont));
    Mont* mq = (Mont*)xalloc(sizeof(Mont));
    bool ok = false;
    if (mp && mq && mont_init(*mp, pp, pl) && mont_init(*mq, qq, ql)) {
        u64 cp[BN_MAX], cq[BN_MAX], m1[BN_MAX], m2[BN_MAX], t[BN_MAX], t2[BN_MAX];
        bn_mod(cp, c, nl, pp, pl);
        bn_mod(cq, c, nl, qq, ql);
        to_mont(*mp, t, cp);
        mont_pow(*mp, t2, t, dp, pl);
        from_mont(*mp, m1, t2);                         // m1 = c^dp mod p
        to_mont(*mq, t, cq);
        mont_pow(*mq, t2, t, dq, ql);
        from_mont(*mq, m2, t2);                         // m2 = c^dq mod q
        // h = qinv * (m1 - m2) mod p
        u64 m2p[BN_MAX];
        bn_zero(m2p, pl);
        bn_mod(m2p, m2, ql, pp, pl);
        u64 diff[BN_MAX];
        mont_sub(*mp, diff, m1, m2p);
        u64 dm[BN_MAX], qm[BN_MAX], hm[BN_MAX], h[BN_MAX];
        to_mont(*mp, dm, diff);
        to_mont(*mp, qm, qi);
        mont_mul(*mp, hm, dm, qm);
        from_mont(*mp, h, hm);
        // m = m2 + h*q
        u64 prod[2 * BN_MAX];
        bn_mul_full(prod, h, pl, qq, ql);
        int tl = pl + ql;
        u64 m[2 * BN_MAX];
        bn_zero(m, tl + 1);
        for (int i = 0; i < ql; ++i) m[i] = m2[i];
        u64 carry = 0;
        for (int i = 0; i < tl; ++i) {
            unsigned __int128 s = (unsigned __int128)prod[i] + m[i] + carry;
            m[i] = (u64)s;
            carry = (u64)(s >> 64);
        }
        (void)hl;
        // проверка результата открытой экспонентой (защита от сбоев)
        if (carry == 0 && e_be.n > 0) {
            u64 n[BN_MAX], e[BN_MAX];
            bn_from_be(n, nl, n_be.p, k);
            bn_from_be(e, nl, e_be.p, e_be.n);
            Mont* mn = (Mont*)xalloc(sizeof(Mont));
            if (mn && mont_init(*mn, n, nl)) {
                u64 mm[BN_MAX], rm[BN_MAX], r[BN_MAX];
                u64 mfix[BN_MAX];
                bn_zero(mfix, nl);
                for (int i = 0; i < nl && i < tl; ++i) mfix[i] = m[i];
                to_mont(*mn, mm, mfix);
                mont_pow(*mn, rm, mm, e, nl);
                from_mont(*mn, r, rm);
                if (bn_cmp(r, c, nl) == 0 && sig.resize(k)) {
                    bn_to_be(sig.p, k, mfix, nl);
                    ok = true;
                }
            }
            xfree(mn);
        }
    }
    xfree(mp);
    xfree(mq);
    return ok;
}

}  // namespace nek
