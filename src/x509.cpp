// NEKalkan — X.509.
#include "x509.h"
#include "gost3410.h"
#include "rsa.h"
#include "plat.h"
#include "legacy.h"

namespace nek {

const char* const OID_KZ_GOST2015_KEY = "1.2.398.3.10.1.1.2.2";
const char* const OID_KZ_GOST2015_HASH256 = "1.2.398.3.10.1.1.2.2.1";
const char* const OID_KZ_GOST2015_HASH512 = "1.2.398.3.10.1.3.3";
const char* const OID_KZ_GOST2015_SIG = "1.2.398.3.10.1.1.2.3.2";
const char* const OID_KZ_LEGACY_SIG = "1.2.398.3.10.1.1.1.1";
const char* const OID_KZ_LEGACY_SIG_CERT = "1.2.398.3.10.1.1.1.2";
const char* const OID_KZ_LEGACY_HASH = "1.2.398.3.10.1.3.1";
const char* const OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1";

// ---- разбор ----------------------------------------------------------------------

static bool parse_alg_id(Span full_tlv, Span& oid, Span& params) {
    Tlv t;
    Span s = full_tlv;
    if (!der_expect(s, T_SEQUENCE, t)) return false;
    Span c = t.val;
    Tlv o;
    if (!der_expect(c, T_OID, o)) return false;
    oid = o.val;
    params = Span();
    if (c.n) {
        Tlv p;
        Span save = c;
        if (!der_next(c, p)) return false;
        params = Span(save.p, p.hdr.n + p.val.n);
    }
    return true;
}

bool Cert::load(Span d) {
    if (!der.assign(d)) return false;
    Span s = der.span();
    Tlv top;
    if (!der_expect(s, T_SEQUENCE, top)) return false;
    Span cs = top.val;
    Tlv tb, sa, sv;
    if (!der_expect(cs, T_SEQUENCE, tb)) return false;
    tbs = tb.full();
    {
        Span save = cs;
        if (!der_expect(cs, T_SEQUENCE, sa)) return false;
        if (!parse_alg_id(Span(save.p, sa.hdr.n + sa.val.n), sig_alg_oid, sig_alg_params)) return false;
    }
    if (!der_expect(cs, T_BITSTRING, sv) || sv.val.n < 1) return false;
    sig_bits = Span(sv.val.p + 1, sv.val.n - 1);

    Span ts = tb.val;
    Tlv t;
    if (!der_peek(ts, t)) return false;
    if (t.tag == 0xA0) { if (!der_next(ts, t)) return false; }      // version
    if (!der_expect(ts, T_INTEGER, t)) return false;
    serial = t.val;
    if (!der_expect(ts, T_SEQUENCE, t)) return false;
    tbs_sig_alg = t.full();
    {
        Span inner_oid, inner_params;
        if (!parse_alg_id(tbs_sig_alg, inner_oid, inner_params) || !inner_oid.eq(sig_alg_oid)) return false;
    }
    if (!der_expect(ts, T_SEQUENCE, t)) return false;
    issuer = t.full();
    Tlv val;
    if (!der_expect(ts, T_SEQUENCE, val)) return false;
    {
        Span vs = val.val;
        Tlv nb, na;
        if (!der_next(vs, nb) || !der_next(vs, na)) return false;
        if (!asn_time_parse(nb, not_before) || !asn_time_parse(na, not_after)) return false;
    }
    if (!der_expect(ts, T_SEQUENCE, t)) return false;
    subject = t.full();
    Tlv sp;
    if (!der_expect(ts, T_SEQUENCE, sp)) return false;
    spki = sp.full();
    {
        Span ss = sp.val;
        Tlv al, bits;
        Span save = ss;
        if (!der_expect(ss, T_SEQUENCE, al)) return false;
        if (!parse_alg_id(Span(save.p, al.hdr.n + al.val.n), spki_alg_oid, spki_params)) return false;
        if (!der_expect(ss, T_BITSTRING, bits) || bits.val.n < 1) return false;
        spki_bits = Span(bits.val.p + 1, bits.val.n - 1);
    }
    extensions = Span();
    while (ts.n) {
        if (!der_next(ts, t)) return false;
        if (t.tag == 0xA3) {
            Span es = t.val;
            Tlv seq;
            if (!der_expect(es, T_SEQUENCE, seq)) return false;
            extensions = seq.val;
        }
    }
    // BasicConstraints, KeyUsage
    Span v;
    has_bc = bc_ca = false;
    bc_pathlen = -1;
    if (find_ext("2.5.29.19", v)) {
        has_bc = true;
        Tlv seq;
        Span vs = v;
        if (der_expect(vs, T_SEQUENCE, seq)) {
            Span in = seq.val;
            Tlv x;
            if (in.n && der_peek(in, x) && x.tag == T_BOOLEAN) { der_next(in, x); bc_ca = x.val.n && x.val.p[0] != 0; }
            if (in.n && der_peek(in, x) && x.tag == T_INTEGER) {
                der_next(in, x);
                u64 pl;
                if (!int_to_u64(x.val, pl) || pl > 1000000) return false;     // отрицательный/огромный pathLenConstraint — сертификат негоден
                bc_pathlen = (long)pl;
            }
        }
    }
    has_ku = false;
    ku = 0;
    if (find_ext("2.5.29.15", v)) {
        Tlv bs;
        Span vs = v;
        if (der_expect(vs, T_BITSTRING, bs) && bs.val.n >= 1) {
            has_ku = true;
            for (size_t i = 1; i < bs.val.n && i <= 2; ++i)
                for (int b = 0; b < 8; ++b)
                    if (bs.val.p[i] & (0x80 >> b)) ku |= 1u << ((i - 1) * 8 + b);
        }
    }
    return true;
}

bool Cert::find_ext(const char* oid, Span& value, bool* critical) const {
    Span es = extensions;
    while (es.n) {
        Tlv e;
        if (!der_next(es, e) || e.tag != T_SEQUENCE) return false;
        Span in = e.val;
        Tlv o, x;
        if (!der_expect(in, T_OID, o)) return false;
        bool crit = false;
        if (in.n && der_peek(in, x) && x.tag == T_BOOLEAN) { der_next(in, x); crit = x.val.n && x.val.p[0]; }
        if (!der_expect(in, T_OCTETSTRING, x)) return false;
        if (oid_is(o.val, oid)) {
            value = x.val;
            if (critical) *critical = crit;
            return true;
        }
    }
    return false;
}

// ---- имена -----------------------------------------------------------------------------

bool asn_string_to_utf8(u32 tag, Span v, Bytes& out) {
    switch (tag) {
        case T_UTF8: case T_PRINTABLE: case T_IA5:
            return out.append(v);
        case T_T61: {                                 // трактуем как Latin-1
            for (size_t i = 0; i < v.n; ++i) {
                u8 c = v.p[i];
                if (c < 0x80) { if (!out.push(c)) return false; }
                else if (!out.push((u8)(0xC0 | (c >> 6))) || !out.push((u8)(0x80 | (c & 0x3F)))) return false;
            }
            return true;
        }
        case T_BMP: {
            if (v.n % 2) return false;
            Vec<u16> w;
            for (size_t i = 0; i < v.n; i += 2)
                if (!w.push((u16)((v.p[i] << 8) | v.p[i + 1]))) return false;
            return utf16_to_utf8(w.d, w.n, out);
        }
        default:
            return out.append(v);
    }
}

bool name_get(Span name, const char* oid, Bytes& out) {
    Span s = name;
    Tlv seq;
    if (!der_expect(s, T_SEQUENCE, seq)) return false;
    Span rdns = seq.val;
    while (rdns.n) {
        Tlv set;
        if (!der_next(rdns, set) || set.tag != T_SET) return false;
        Span atvs = set.val;
        while (atvs.n) {
            Tlv atv;
            if (!der_next(atvs, atv) || atv.tag != T_SEQUENCE) return false;
            Span in = atv.val;
            Tlv o, v;
            if (!der_expect(in, T_OID, o) || !der_next(in, v)) return false;
            if (oid_is(o.val, oid)) {
                out.clear();
                return asn_string_to_utf8(v.tag, v.val, out);
            }
        }
    }
    return false;
}

// ---- открытый ключ ГОСТ ---------------------------------------------------------------------

bool gost_point_from_spki_bits(Span bits, Span& point) {
    if (bits.n < 2) return false;
    if (bits.p[0] == 0x04) {                       // OCTET STRING (RFC 4491)
        if (bits.p[1] & 0x80) {
            size_t n = bits.p[1] & 0x7F;
            if (2 + n > bits.n) return false;
            point = Span(bits.p + 2 + n, bits.n - 2 - n);
        } else {
            point = Span(bits.p + 2, bits.n - 2);
        }
    } else {
        point = Span(bits.p + 1, bits.n - 1);      // 04||X||Y без обёртки
    }
    return point.n == 64 || point.n == 128;
}

// ---- проверка подписи ----------------------------------------------------------------------------

static HashAlg hash_by_oid(Span oid) {
    if (oid_is(oid, "1.3.14.3.2.26")) return H_SHA1;
    if (oid_is(oid, "2.16.840.1.101.3.4.2.1")) return H_SHA256;
    if (oid_is(oid, "2.16.840.1.101.3.4.2.2")) return H_SHA384;
    if (oid_is(oid, "2.16.840.1.101.3.4.2.3")) return H_SHA512;
    return H_NONE;
}

static HashAlg hash_by_rsa_sigalg(Span oid) {
    if (oid_is(oid, "1.2.840.113549.1.1.5")) return H_SHA1;
    if (oid_is(oid, "1.2.840.113549.1.1.11")) return H_SHA256;
    if (oid_is(oid, "1.2.840.113549.1.1.12")) return H_SHA384;
    if (oid_is(oid, "1.2.840.113549.1.1.13")) return H_SHA512;
    return H_NONE;
}

static bool verify_legacy_2001(const Cert& cert, Span data, Span sig, bool* unsupported) {
    // KeyParams = SEQUENCE { curveOID, digestOID }; ключ — 64 байта X||Y (little-endian)
    Span ps = cert.spki_params;
    Tlv seq, co;
    if (!der_expect(ps, T_SEQUENCE, seq)) return false;
    Span in = seq.val;
    if (!der_expect(in, T_OID, co)) return false;
    int cid = gost2001_curve_by_oid(co.val);
    if (cid < 0) { if (unsupported) *unsupported = true; return false; }
    Span point;
    if (!gost_point_from_spki_bits(cert.spki_bits, point) || point.n != 64 || sig.n != 64) return false;
    u8 dg[32];
    gost341194_kz(data, dg);
    const GostCurve* c = gost_curve_id(cid);
    return c && gost3410_verify(c, point, Span(dg, 32), sig);
}

bool verify_with_cert_key(const Cert& cert, Span sig_alg, Span digest_alg, Span data, Span sig, bool* unsupported) {
    if (unsupported) *unsupported = false;
    if (oid_is(sig_alg, OID_KZ_LEGACY_SIG) || oid_is(sig_alg, OID_KZ_LEGACY_SIG_CERT)) return verify_legacy_2001(cert, data, sig, unsupported);
    if (oid_is(cert.spki_alg_oid, OID_KZ_GOST2015_KEY)) {
        if (!oid_is(sig_alg, OID_KZ_GOST2015_SIG)) { if (unsupported) *unsupported = true; return false; }
        size_t size = sig.n / 2;
        if (size != 32 && size != 64) { if (unsupported) *unsupported = true; return false; }
        Span point;
        if (!gost_point_from_spki_bits(cert.spki_bits, point)) return false;
        if (point.n != 2 * size) { if (unsupported) *unsupported = true; return false; }
        u8 digest[64];
        hash_data(size == 32 ? H_STREEBOG256 : H_STREEBOG512, data, digest);
        const GostCurve* c = gost_curve((int)size);
        return c && gost3410_verify(c, point, Span(digest, size), sig);
    }
    if (oid_is(cert.spki_alg_oid, OID_RSA_ENCRYPTION)) {
        HashAlg h = hash_by_rsa_sigalg(sig_alg);
        if (h == H_NONE && oid_is(sig_alg, OID_RSA_ENCRYPTION)) h = hash_by_oid(digest_alg);
        if (h == H_NONE) { if (unsupported) *unsupported = true; return false; }
        // RSAPublicKey ::= SEQUENCE { n INTEGER, e INTEGER }
        Span s = cert.spki_bits;
        Tlv seq, n, e;
        if (!der_expect(s, T_SEQUENCE, seq)) return false;
        Span in = seq.val;
        if (!der_expect(in, T_INTEGER, n) || !der_expect(in, T_INTEGER, e)) return false;
        u8 digest[64];
        hash_data(h, data, digest);
        return rsa_pkcs1_verify(int_magnitude(n.val), int_magnitude(e.val), h, Span(digest, hash_size(h)), sig);
    }
    if (unsupported) *unsupported = true;
    return false;
}

bool cert_verify_signature(const Cert& cert, const Cert& issuer, bool* unsupported) {
    return verify_with_cert_key(issuer, cert.sig_alg_oid, Span(), cert.tbs, cert.sig_bits, unsupported);
}

// ---- цепочка ------------------------------------------------------------------------------------

static bool is_ca_cert(const Cert& c) { return c.has_bc && c.bc_ca; }
static bool key_cert_sign_ok(const Cert& c) { return !c.has_ku || (c.ku & (1u << 5)); }

u32 chain_validate(const Cert& cert, const Cert* const* pool, size_t pool_n, const Cert* const* anchors, size_t anchors_n,
                   i64 check_time, u32 flags) {
    if (check_time == 0) check_time = plat_unix_time();
    const Cert* chain[40];
    size_t cn = 0;
    chain[cn++] = &cert;
    const Cert* anchor = 0;
    const Cert* cur = &cert;
    for (int guard = 0; guard < 40; ++guard) {
        // якорь: издатель текущего = субъект якоря
        for (size_t i = 0; i < anchors_n; ++i)
            if (anchors[i]->subject.eq(cur->issuer)) { anchor = anchors[i]; break; }
        if (anchor) break;
        const Cert* nxt = 0;
        for (size_t i = 0; i < pool_n; ++i) {
            if (!pool[i]->subject.eq(cur->issuer)) continue;
            bool seen = false;
            for (size_t k = 0; k < cn; ++k) if (chain[k] == pool[i]) seen = true;
            if (!seen) { nxt = pool[i]; break; }
        }
        if (!nxt || cn >= 39) return KCR_CACERTNOTFOUND;
        chain[cn++] = nxt;
        cur = nxt;
    }
    if (!anchor) return KCR_CACERTNOTFOUND;
    if (!(flags & CHAIN_NO_TIME)) {
        for (size_t i = 0; i < cn; ++i)
            if (check_time < chain[i]->not_before || check_time > chain[i]->not_after) return KCR_CERTTIMEINVALID;
        if (check_time < anchor->not_before || check_time > anchor->not_after) return KCR_CERTTIMEINVALID;
    }
    for (size_t i = 1; i < cn; ++i) {
        const Cert* n = chain[i];
        if (!is_ca_cert(*n) || !key_cert_sign_ok(*n)) return KCR_CACERTNOTFOUND;
        if (n->bc_pathlen >= 0 && (long)(i - 1) > n->bc_pathlen) return KCR_CACERTNOTFOUND;
    }
    if (is_ca_cert(*anchor) && anchor->bc_pathlen >= 0 && (long)(cn - 1) > anchor->bc_pathlen) return KCR_CACERTNOTFOUND;
    if (!is_ca_cert(*anchor) || !key_cert_sign_ok(*anchor)) {
        // самоподписанный якорь без признака УЦ допускаем только если это сам проверяемый сертификат
        if (!(cn == 1 && anchor == &cert)) return KCR_CACERTNOTFOUND;
    }
    for (size_t i = 0; i < cn; ++i) {
        const Cert* issuer = (i + 1 < cn) ? chain[i + 1] : anchor;
        if (!cert_verify_signature(*chain[i], *issuer)) return KCR_CACERTNOTFOUND;
    }
    return KCR_OK;
}

}  // namespace nek
