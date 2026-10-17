// NEKalkan — CRL.
#include "crl.h"

namespace nek {

bool Crl::load(Span data) {
    Bytes raw;
    if (looks_like_pem(data)) {
        if (!pem_decode(data, raw)) return false;
    } else if (data.n && data.p[0] == 0x30) {
        if (!raw.append(data)) return false;
    } else {
        if (!b64_decode(data, raw)) return false;
    }
    if (!der.assign(raw.span())) return false;
    Span s = der.span();
    Tlv top, tb, sa, sv;
    if (!der_expect(s, T_SEQUENCE, top)) return false;
    Span cs = top.val;
    if (!der_expect(cs, T_SEQUENCE, tb)) return false;
    tbs = tb.full();
    if (!der_expect(cs, T_SEQUENCE, sa)) return false;
    {
        Span as = sa.val;
        Tlv o;
        if (!der_expect(as, T_OID, o)) return false;
        sig_alg_oid = o.val;
    }
    if (!der_expect(cs, T_BITSTRING, sv) || sv.val.n < 1) return false;
    sig_bits = Span(sv.val.p + 1, sv.val.n - 1);

    Span ts = tb.val;
    Tlv t;
    if (!der_peek(ts, t)) return false;
    if (t.tag == T_INTEGER) der_next(ts, t);                 // version
    if (!der_expect(ts, T_SEQUENCE, t)) return false;        // signature alg
    if (!der_expect(ts, T_SEQUENCE, t)) return false;
    issuer = t.full();
    if (!der_next(ts, t) || !asn_time_parse(t, this_update)) return false;
    has_next = false;
    if (ts.n && der_peek(ts, t) && (t.tag == T_UTCTIME || t.tag == T_GENTIME)) {
        der_next(ts, t);
        if (!asn_time_parse(t, next_update)) return false;
        has_next = true;
    }
    revoked = Span();
    if (ts.n && der_peek(ts, t) && t.tag == T_SEQUENCE) { der_next(ts, t); revoked = t.val; }
    is_delta = false;
    if (ts.n && der_peek(ts, t) && t.tag == 0xA0) {
        der_next(ts, t);
        Span es = t.val;
        Tlv seq;
        if (der_expect(es, T_SEQUENCE, seq)) {
            Span in = seq.val;
            while (in.n) {
                Tlv e, o;
                if (!der_next(in, e) || e.tag != T_SEQUENCE) break;
                Span ein = e.val;
                if (der_expect(ein, T_OID, o) && oid_is(o.val, "2.5.29.27")) is_delta = true;
            }
        }
    }
    return true;
}

bool Crl::verify(const Cert& iss) const {
    bool unsupported = false;
    if (!iss.subject.eq(issuer)) return false;
    return verify_with_cert_key(iss, sig_alg_oid, Span(), tbs, sig_bits, &unsupported);
}

bool Crl::is_revoked(Span serial, i64* when) const {
    Span rs = revoked;
    while (rs.n) {
        Tlv e;
        if (!der_next(rs, e) || e.tag != T_SEQUENCE) return false;
        Span in = e.val;
        Tlv sn, dt;
        if (!der_expect(in, T_INTEGER, sn)) return false;
        if (int_magnitude(sn.val).eq(int_magnitude(serial))) {
            if (when && der_next(in, dt)) asn_time_parse(dt, *when);
            return true;
        }
    }
    return false;
}

}  // namespace nek
