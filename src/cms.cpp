// NEKalkan — CMS SignedData.
#include "cms.h"
#include "gost3410.h"
#include "rsa.h"
#include "plat.h"

namespace nek {

static const char* const OID_SIGNED_DATA = "1.2.840.113549.1.7.2";
static const char* const OID_DATA = "1.2.840.113549.1.7.1";
static const char* const OID_CONTENT_TYPE = "1.2.840.113549.1.9.3";
static const char* const OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4";
static const char* const OID_SIGNING_TIME = "1.2.840.113549.1.9.5";
static const char* const OID_SIGNING_CERT_V2 = "1.2.840.113549.1.9.16.2.47";
static const char* const OID_TIMESTAMP_TOKEN = "1.2.840.113549.1.9.16.2.14";
static const char* const OID_SHA256 = "2.16.840.1.101.3.4.2.1";
static const char* const OID_RSA_SHA256 = "1.2.840.113549.1.1.11";

CmsMessage::~CmsMessage() {
    for (size_t i = 0; i < certs.n; ++i) delete certs.d[i];
}

// содержимое OCTET STRING (простого или составного)
static bool octets_join(const Tlv& t, Bytes& out) {
    if (t.tag == T_OCTETSTRING) return out.append(t.val);
    if (t.tag == 0x24) {
        Span s = t.val;
        while (s.n) {
            Tlv c;
            if (!der_next(s, c) || !octets_join(c, out)) return false;
        }
        return true;
    }
    return false;
}

bool CmsMessage::parse(Span cms) {
    if (!ber_to_der(cms, der)) return (fail_line = __LINE__, false);
    Span s = der.span();
    Tlv ci, oid, ex, sd;
    if (!der_expect(s, T_SEQUENCE, ci)) return (fail_line = __LINE__, false);
    Span in = ci.val;
    if (!der_expect(in, T_OID, oid) || !oid_is(oid.val, OID_SIGNED_DATA)) return (fail_line = __LINE__, false);
    if (!der_expect(in, 0xA0, ex)) return (fail_line = __LINE__, false);
    Span exs = ex.val;
    if (!der_expect(exs, T_SEQUENCE, sd)) return (fail_line = __LINE__, false);
    Span sdin = sd.val;
    Tlv ver, digalgs, encap;
    if (!der_expect(sdin, T_INTEGER, ver) || !der_expect(sdin, T_SET, digalgs) || !der_expect(sdin, T_SEQUENCE, encap))
        return (fail_line = __LINE__, false);
    Span ein = encap.val;
    Tlv ect;
    if (!der_expect(ein, T_OID, ect) || !oid_to_str(ect.val, econtent_type, sizeof(econtent_type))) return (fail_line = __LINE__, false);
    has_embedded = false;
    content.clear();
    if (ein.n) {
        Tlv e0;
        if (!der_expect(ein, 0xA0, e0)) return (fail_line = __LINE__, false);
        Span e0s = e0.val;
        Tlv oc;
        if (der_next(e0s, oc)) {
            if (!octets_join(oc, content)) {
                // не OCTET STRING (например, вложенная структура) — берём как есть
                content.clear();
                if (!content.append(oc.val)) return (fail_line = __LINE__, false);
            }
            has_embedded = true;
        }
    }
    Tlv t;
    while (sdin.n) {
        Span save = sdin;
        if (!der_next(sdin, t)) return (fail_line = __LINE__, false);
        if (t.tag == 0xA0) {                         // certificates
            Span cs = t.val;
            while (cs.n) {
                Tlv c;
                if (!der_next(cs, c)) return (fail_line = __LINE__, false);
                if (c.tag != T_SEQUENCE) continue;
                Cert* cert = new Cert();
                if (!cert) return (fail_line = __LINE__, false);
                if (!cert->load(c.full())) { delete cert; continue; }
                if (!certs.push(cert)) { delete cert; return (fail_line = __LINE__, false); }
            }
        } else if (t.tag == 0xA1) {
            // crls — пропускаем
        } else if (t.tag == T_SET) {                // signerInfos
            Span ss = t.val;
            while (ss.n) {
                Tlv si;
                if (!der_next(ss, si) || si.tag != T_SEQUENCE) return (fail_line = __LINE__, false);
                if (!signer_infos.push(si.full())) return (fail_line = __LINE__, false);
            }
        } else {
            sdin = save;
            return (fail_line = __LINE__, false);
        }
    }
    return true;
}

// ---- проверка ----------------------------------------------------------------------------

static bool spans_equal_int(Span a, Span b) { return int_magnitude(a).eq(int_magnitude(b)); }

static int find_signer_cert(const Vec<Cert*>& certs, const Tlv& sid) {
    if (!certs.n) return -1;
    if (sid.tag == T_SEQUENCE) {
        Span in = sid.val;
        Tlv issuer, serial;
        if (!der_next(in, issuer) || !der_expect(in, T_INTEGER, serial)) return -1;
        int by_serial = -1, count = 0;
        for (size_t i = 0; i < certs.n; ++i) {
            if (!spans_equal_int(certs.d[i]->serial, serial.val)) continue;
            if (certs.d[i]->issuer.eq(issuer.full())) return (int)i;
            by_serial = (int)i;
            ++count;
        }
        if (count == 1) return by_serial;
        return -1;
    }
    if (sid.tag == 0x80) {                           // subjectKeyIdentifier
        for (size_t i = 0; i < certs.n; ++i) {
            Span v;
            if (!certs.d[i]->find_ext("2.5.29.14", v)) continue;
            Tlv o;
            Span vs = v;
            if (der_expect(vs, T_OCTETSTRING, o) && o.val.eq(sid.val)) return (int)i;
        }
    }
    return -1;
}

// Время из токена метки времени (RFC 3161): ContentInfo(SignedData) → eContent(TSTInfo) → genTime
static bool parse_tsa_time(Span token, i64& out) {
    Bytes der;
    if (!ber_to_der(token, der)) return false;
    Span s = der.span();
    Tlv ci, oid, ex, sd;
    if (!der_expect(s, T_SEQUENCE, ci)) return false;
    Span in = ci.val;
    if (!der_expect(in, T_OID, oid) || !der_expect(in, 0xA0, ex)) return false;
    Span exs = ex.val;
    if (!der_expect(exs, T_SEQUENCE, sd)) return false;
    Span sdin = sd.val;
    Tlv ver, algs, encap;
    if (!der_expect(sdin, T_INTEGER, ver) || !der_expect(sdin, T_SET, algs) || !der_expect(sdin, T_SEQUENCE, encap)) return false;
    Span ein = encap.val;
    Tlv ect, e0, oc;
    if (!der_expect(ein, T_OID, ect) || !der_expect(ein, 0xA0, e0)) return false;
    Span e0s = e0.val;
    if (!der_next(e0s, oc)) return false;
    Bytes tst;
    if (!octets_join(oc, tst)) return false;
    Span ts = tst.span();
    Tlv tseq;
    if (!der_expect(ts, T_SEQUENCE, tseq)) return false;
    Span t = tseq.val;
    Tlv x;
    // version, policy, messageImprint, serialNumber, genTime
    for (int i = 0; i < 4; ++i) if (!der_next(t, x)) return false;
    if (!der_next(t, x)) return false;
    return asn_time_parse(x, out);
}

struct DigestFn {
    HashAlg alg;
    void compute(Span data, u8* out) const { hash_data(alg, data, out); }
};

bool CmsMessage::verify(const Bytes* detached, const Cert* const* anchors, size_t anchors_n, const Cert* const* pool, size_t pool_n,
                        i64 check_time, u32 chain_flags) {
    Span payload = has_embedded ? content.span() : (detached ? detached->span() : Span());
    if (!has_embedded && detached) { content.clear(); content.append(detached->span()); payload = content.span(); }
    signers.n = 0;
    for (size_t si_i = 0; si_i < signer_infos.n; ++si_i) {
        SignerResult r;
        memset(&r, 0, sizeof(r));
        r.digest_ok = r.signature_ok = r.chain_ok = r.time_ok = r.cades_ok = -1;
        r.state = "unknown";
        r.cert_index = -1;
        Span sis = signer_infos[si_i];
        Tlv seq;
        if (!der_expect(sis, T_SEQUENCE, seq)) { r.state = "error: bad_signer_info"; signers.push(r); continue; }
        Span in = seq.val;
        Tlv ver, sid, dalg, sattrs, salg, sig, uattrs;
        bool has_sattrs = false, has_uattrs = false, has_scv2 = false;
        Span scv2_value;
        if (!der_expect(in, T_INTEGER, ver) || !der_next(in, sid) || !der_expect(in, T_SEQUENCE, dalg)) { r.state = "error: bad_signer_info"; signers.push(r); continue; }
        Tlv peek;
        if (in.n && der_peek(in, peek) && peek.tag == 0xA0) { der_next(in, sattrs); has_sattrs = true; }
        if (!der_expect(in, T_SEQUENCE, salg) || !der_expect(in, T_OCTETSTRING, sig)) { r.state = "error: bad_signer_info"; signers.push(r); continue; }
        if (in.n && der_peek(in, peek) && peek.tag == 0xA1) { der_next(in, uattrs); has_uattrs = true; }

        Span dain = dalg.val, sain = salg.val;
        Tlv doid, soid;
        if (!der_expect(dain, T_OID, doid) || !der_expect(sain, T_OID, soid)) { r.state = "error: bad_alg"; signers.push(r); continue; }
        oid_to_str(doid.val, r.digest_oid, sizeof(r.digest_oid));
        oid_to_str(soid.val, r.sig_oid, sizeof(r.sig_oid));

        bool legacy = oid_is(doid.val, OID_KZ_LEGACY_HASH) || oid_is(soid.val, OID_KZ_LEGACY_SIG) || oid_is(soid.val, OID_KZ_LEGACY_SIG_CERT);
        int ci = find_signer_cert(certs, sid);
        r.cert_index = ci;

        // функция хэша
        HashAlg halg = H_NONE;
        const Cert* cert = ci >= 0 ? certs.d[ci] : 0;
        if (legacy) {
            if (!oid_is(doid.val, OID_KZ_LEGACY_HASH) || (!oid_is(soid.val, OID_KZ_LEGACY_SIG) && !oid_is(soid.val, OID_KZ_LEGACY_SIG_CERT))) {
                r.state = "unsupported_oid"; signers.push(r); continue;
            }
            halg = H_GOST94;
        } else if (cert && oid_is(cert->spki_alg_oid, OID_RSA_ENCRYPTION)) {
            if (oid_is(soid.val, "1.2.840.113549.1.1.5")) halg = H_SHA1;
            else if (oid_is(soid.val, "1.2.840.113549.1.1.11")) halg = H_SHA256;
            else if (oid_is(soid.val, "1.2.840.113549.1.1.12")) halg = H_SHA384;
            else if (oid_is(soid.val, "1.2.840.113549.1.1.13")) halg = H_SHA512;
            else if (oid_is(soid.val, OID_RSA_ENCRYPTION)) {
                if (oid_is(doid.val, "1.3.14.3.2.26")) halg = H_SHA1;
                else if (oid_is(doid.val, "2.16.840.1.101.3.4.2.1")) halg = H_SHA256;
                else if (oid_is(doid.val, "2.16.840.1.101.3.4.2.2")) halg = H_SHA384;
                else if (oid_is(doid.val, "2.16.840.1.101.3.4.2.3")) halg = H_SHA512;
            }
            if (halg == H_NONE) { r.state = "unsupported_oid"; signers.push(r); continue; }
        } else {
            if ((!oid_is(doid.val, OID_KZ_GOST2015_HASH256) && !oid_is(doid.val, OID_KZ_GOST2015_HASH512)) ||
                !oid_is(soid.val, OID_KZ_GOST2015_SIG)) { r.state = "unsupported_oid"; signers.push(r); continue; }
            size_t size = sig.val.n / 2;
            halg = size == 64 ? H_STREEBOG512 : H_STREEBOG256;
        }
        if (!has_sattrs && !legacy) { r.state = "no_signed_attrs"; signers.push(r); continue; }

        // подписанные атрибуты (у устаревших подписей их может не быть — тогда подписывается само содержимое)
        if (has_sattrs) {
            char seen[16][64];
            int nseen = 0;
            bool dup = false;
            Span as = sattrs.val;
            Span md_values, ct_values;
            bool has_md = false, has_ct = false;
            has_scv2 = false;
            while (as.n) {
                Tlv a;
                if (!der_next(as, a) || a.tag != T_SEQUENCE) { dup = true; break; }
                Span ain = a.val;
                Tlv ao, av;
                if (!der_expect(ain, T_OID, ao) || !der_expect(ain, T_SET, av)) { dup = true; break; }
                char o[64];
                if (!oid_to_str(ao.val, o, sizeof(o))) { dup = true; break; }
                for (int k = 0; k < nseen; ++k) {
                    size_t j = 0;
                    while (seen[k][j] && seen[k][j] == o[j]) ++j;
                    if (!seen[k][j] && !o[j]) dup = true;
                }
                if (nseen < 16) { size_t j = 0; while ((seen[nseen][j] = o[j])) ++j; ++nseen; }
                if (oid_is(ao.val, OID_MESSAGE_DIGEST)) { has_md = true; md_values = av.val; }
                else if (oid_is(ao.val, OID_CONTENT_TYPE)) { has_ct = true; ct_values = av.val; }
                else if (oid_is(ao.val, OID_SIGNING_CERT_V2)) { has_scv2 = true; scv2_value = av.val; }
                else if (oid_is(ao.val, OID_SIGNING_TIME)) {
                    Span vs = av.val;
                    Tlv tt;
                    if (der_next(vs, tt) && asn_time_parse(tt, r.signing_time)) r.has_time = true;
                }
            }
            if (dup || !has_md || !has_ct) { r.state = "bad_signed_attrs"; signers.push(r); continue; }
            Tlv mdv, ctv;
            Span m = md_values, c2 = ct_values;
            if (!der_next(m, mdv) || m.n || mdv.tag != T_OCTETSTRING || !der_next(c2, ctv) || c2.n || ctv.tag != T_OID) {
                r.state = "bad_signed_attrs"; signers.push(r); continue;
            }
            if (!oid_is(ctv.val, econtent_type)) { r.state = "bad_signed_attrs"; signers.push(r); continue; }
            u8 dg[64];
            hash_data(halg, payload, dg);
            r.digest_ok = (mdv.val.n == hash_size(halg) && ct_eq(mdv.val.p, dg, mdv.val.n)) ? 1 : 0;
        }
        if (has_uattrs) {
            Span us = uattrs.val;
            while (us.n) {
                Tlv a;
                if (!der_next(us, a) || a.tag != T_SEQUENCE) break;
                Span ain = a.val;
                Tlv ao;
                if (der_expect(ain, T_OID, ao) && oid_is(ao.val, OID_TIMESTAMP_TOKEN)) {
                    r.has_tsa = true;
                    Tlv vs, tok;
                    if (der_expect(ain, T_SET, vs)) {
                        Span v = vs.val;
                        if (der_next(v, tok) && parse_tsa_time(tok.full(), r.tsa_time)) r.has_tsa_time = true;
                    }
                }
            }
        }
        if (!cert) { r.state = "no_certificate"; signers.push(r); continue; }
        if (has_scv2) {
            // ESSCertIDv2: [hashAlgorithm DEFAULT sha256] certHash OCTET STRING
            r.cades_ok = 0;
            Span v = scv2_value;
            Tlv top, certs_seq, id;
            if (der_next(v, top) && top.tag == T_SEQUENCE) {
                Span a = top.val;
                if (der_expect(a, T_SEQUENCE, certs_seq)) {
                    Span b = certs_seq.val;
                    if (der_expect(b, T_SEQUENCE, id)) {
                        Span c = id.val;
                        HashAlg ha = H_SHA256;
                        Tlv x;
                        if (der_peek(c, x) && x.tag == T_SEQUENCE) {
                            der_next(c, x);
                            Span ai = x.val;
                            Tlv ao;
                            if (der_expect(ai, T_OID, ao)) {
                                if (oid_is(ao.val, "1.3.14.3.2.26")) ha = H_SHA1;
                                else if (oid_is(ao.val, "2.16.840.1.101.3.4.2.2")) ha = H_SHA384;
                                else if (oid_is(ao.val, "2.16.840.1.101.3.4.2.3")) ha = H_SHA512;
                                else if (!oid_is(ao.val, "2.16.840.1.101.3.4.2.1")) ha = H_NONE;
                            }
                        }
                        Tlv ch;
                        if (ha != H_NONE && der_expect(c, T_OCTETSTRING, ch)) {
                            u8 h[64];
                            hash_data(ha, cert->der.span(), h);
                            r.cades_ok = (ch.val.n == hash_size(ha) && ct_eq(ch.val.p, h, ch.val.n)) ? 1 : 0;
                        }
                    }
                }
            }
        }

        // подпись над SET OF signedAttrs (тег [0] → SET) либо над самим содержимым (устаревший формат без атрибутов)
        Bytes set_der;
        if (has_sattrs) {
            if (!set_der.append(sattrs.full())) { r.state = "error: memory"; signers.push(r); continue; }
            set_der.p[0] = 0x31;
        } else {
            r.digest_ok = 1;
            if (!set_der.append(payload)) { r.state = "error: memory"; signers.push(r); continue; }
        }
        bool unsupported = false;
        r.signature_ok = verify_with_cert_key(*cert, soid.val, doid.val, set_der.span(), sig.val, &unsupported) ? 1 : 0;
        if (unsupported) { r.state = "unsupported_oid"; signers.push(r); continue; }

        if (anchors_n) {
            Vec<const Cert*> all;
            for (size_t i = 0; i < certs.n; ++i) if (certs.d[i] != cert) all.push(certs.d[i]);
            for (size_t i = 0; i < pool_n; ++i) all.push(pool[i]);
            u32 rc = chain_validate(*cert, all.d, all.n, anchors, anchors_n, check_time, chain_flags);
            r.chain_ok = rc == KCR_OK ? 1 : 0;
            r.chain_rc = rc;
        }
        if (check_time != 0) r.time_ok = (check_time >= cert->not_before && check_time <= cert->not_after) ? 1 : 0;
        bool ok = r.digest_ok == 1 && r.signature_ok == 1 && r.chain_ok != 0 && r.time_ok != 0;
        r.state = ok ? "ok" : "failed";
        signers.push(r);
    }
    return signers.n > 0;
}

// ---- формирование ------------------------------------------------------------------------------

static bool hash_key_data(const SignKey& k, Span data, u8* out, size_t& n, HashAlg& alg) {
    if (k.type == KEY_GOST2015) {
        alg = k.gost_size == 64 ? H_STREEBOG512 : H_STREEBOG256;
    } else if (k.type == KEY_RSA) {
        alg = H_SHA256;
    } else return false;
    hash_data(alg, data, out);
    n = hash_size(alg);
    return true;
}

static bool sign_digest(const SignKey& k, Span digest, Bytes& sig) {
    if (k.type == KEY_GOST2015) {
        const GostCurve* c = gost_curve(k.gost_size);
        if (!c || !sig.resize(2 * (size_t)k.gost_size)) return false;
        return gost3410_sign(c, k.gost_priv.span(), digest, sig.p);
    }
    if (k.type == KEY_RSA) return rsa_pkcs1_sign(k.rsa, H_SHA256, digest, sig);
    return false;
}

bool sign_prehashed(const SignKey& key, Span digest, Bytes& sig) { return sign_digest(key, digest, sig); }

bool raw_sign(const SignKey& key, Span data, Bytes& sig) {
    u8 dg[64];
    size_t dn;
    HashAlg alg;
    if (!hash_key_data(key, data, dg, dn, alg)) return false;
    return sign_digest(key, Span(dg, dn), sig);
}

bool raw_verify(const Cert& cert, Span data, Span sig, bool prehashed) {
    if (oid_is(cert.spki_alg_oid, OID_KZ_GOST2015_KEY)) {
        size_t size = sig.n / 2;
        Span point;
        if ((size != 32 && size != 64) || !gost_point_from_spki_bits(cert.spki_bits, point) || point.n != 2 * size) return false;
        u8 dg[64];
        Span digest;
        if (prehashed) digest = data;
        else {
            hash_data(size == 64 ? H_STREEBOG512 : H_STREEBOG256, data, dg);
            digest = Span(dg, size);
        }
        const GostCurve* c = gost_curve((int)size);
        return c && gost3410_verify(c, point, digest, sig);
    }
    if (oid_is(cert.spki_alg_oid, OID_RSA_ENCRYPTION)) {
        Bytes oid;
        oid_encode(OID_RSA_SHA256, oid);
        bool u = false;
        return verify_with_cert_key(cert, oid.span(), Span(), data, sig, &u);
    }
    return false;
}

static int cmp_bytes(const Bytes& a, const Bytes& b) {
    size_t n = a.n < b.n ? a.n : b.n;
    int c = memcmp(a.p, b.p, n);
    if (c) return c;
    return a.n < b.n ? -1 : (a.n > b.n ? 1 : 0);
}

static int cmp_span(Span a, Span b) {
    size_t n = a.n < b.n ? a.n : b.n;
    int c = memcmp(a.p, b.p, n);
    if (c) return c;
    return a.n < b.n ? -1 : (a.n > b.n ? 1 : 0);
}

static bool make_attr(const char* oid, Span value_der, Bytes& out) {
    DerOut d;
    d.begin(T_SEQUENCE);
    d.oid(oid);
    d.begin(T_SET);
    d.raw(value_der);
    d.end();
    d.end();
    if (!d.ok()) return false;
    out = static_cast<Bytes&&>(d.b);
    return true;
}

// DER SET OF: элементы упорядочиваются по их кодировке.
static bool der_set_of(Vec<Span>& items, Bytes& out) {
    for (size_t i = 0; i < items.n; ++i)
        for (size_t j = i + 1; j < items.n; ++j)
            if (cmp_span(items[j], items[i]) < 0) { Span t = items[i]; items[i] = items[j]; items[j] = t; }
    Bytes body;
    for (size_t i = 0; i < items.n; ++i) if (!body.append(items[i])) return false;
    return der_wrap(T_SET, body.span(), out);
}

struct SignerParts {
    Bytes signer_info;       // TLV SignerInfo
    const char* digest_oid;
    bool gost;
};

// Строит SignerInfo для подписи значения content_digest (хэш содержимого тем же алгоритмом, что у ключа).
static bool build_signer_info(const SignKey& key, Span content_digest, i64 stime, SignerParts& out) {
    if (!key.cert) return false;
    const Cert& cert = *key.cert;
    bool gost = key.type == KEY_GOST2015;
    out.gost = gost;
    out.digest_oid = gost ? (key.gost_size == 64 ? OID_KZ_GOST2015_HASH512 : OID_KZ_GOST2015_HASH256) : OID_SHA256;
    const char* sig_oid = gost ? OID_KZ_GOST2015_SIG : OID_RSA_SHA256;

    Bytes attrs[4];
    {
        DerOut v;
        v.oid(OID_DATA);
        if (!make_attr(OID_CONTENT_TYPE, v.b.span(), attrs[0])) return false;
    }
    {
        DerOut v;
        v.time(stime);
        if (!make_attr(OID_SIGNING_TIME, v.b.span(), attrs[1])) return false;
    }
    {
        u8 ch[32];
        hash_data(H_SHA256, cert.der.span(), ch);
        DerOut v;
        v.begin(T_SEQUENCE); v.begin(T_SEQUENCE); v.begin(T_SEQUENCE);
        v.octets(Span(ch, 32));
        v.end(); v.end(); v.end();
        if (!v.ok() || !make_attr(OID_SIGNING_CERT_V2, v.b.span(), attrs[2])) return false;
    }
    {
        DerOut v;
        v.octets(content_digest);
        if (!make_attr(OID_MESSAGE_DIGEST, v.b.span(), attrs[3])) return false;
    }
    int order[4] = {0, 1, 2, 3};
    for (int i = 0; i < 4; ++i)
        for (int j = i + 1; j < 4; ++j)
            if (cmp_bytes(attrs[order[j]], attrs[order[i]]) < 0) { int t = order[i]; order[i] = order[j]; order[j] = t; }
    Bytes attrs_sorted;
    for (int i = 0; i < 4; ++i) if (!attrs_sorted.append(attrs[order[i]].span())) return false;
    Bytes attrs_set;
    if (!der_wrap(T_SET, attrs_sorted.span(), attrs_set)) return false;

    u8 sdg[64];
    size_t sdn;
    HashAlg a2;
    if (!hash_key_data(key, attrs_set.span(), sdg, sdn, a2)) return false;
    Bytes signature;
    if (!sign_digest(key, Span(sdg, sdn), signature)) return false;

    DerOut o;
    o.begin(T_SEQUENCE);
    o.integer_u64(1);
    o.begin(T_SEQUENCE);
    o.raw(cert.issuer);
    o.prim(T_INTEGER, cert.serial);
    o.end();
    o.begin(T_SEQUENCE); o.oid(out.digest_oid); if (gost) o.null(); o.end();
    o.begin(0xA0); o.raw(attrs_sorted.span()); o.end();
    o.begin(T_SEQUENCE); o.oid(sig_oid); o.null(); o.end();
    o.octets(signature.span());
    o.end();
    if (!o.ok()) return false;
    out.signer_info = static_cast<Bytes&&>(o.b);
    return true;
}

bool cms_sign(const SignKey& key, Span data, const CmsSignOptions& opt, Bytes& out) {
    if (!key.cert) return false;
    const Cert& cert = *key.cert;
    u8 dg[64];
    size_t dn;
    HashAlg alg;
    Span digest;
    if (opt.precomputed_digest.n) {
        digest = opt.precomputed_digest;
        if (!hash_key_data(key, Span(), dg, dn, alg) || digest.n != dn) return false;     // длина хэша должна соответствовать ключу
    } else {
        if (!hash_key_data(key, data, dg, dn, alg)) return false;
        digest = Span(dg, dn);
    }
    i64 stime = opt.signing_time ? opt.signing_time : plat_unix_time();
    SignerParts sp;
    if (!build_signer_info(key, digest, stime, sp)) return false;
    bool detached = opt.detached || opt.precomputed_digest.n;

    DerOut o;
    o.begin(T_SEQUENCE);
    o.oid(OID_SIGNED_DATA);
    o.begin(0xA0);
    o.begin(T_SEQUENCE);
    o.integer_u64(1);
    o.begin(T_SET);
    o.begin(T_SEQUENCE); o.oid(sp.digest_oid); if (sp.gost) o.null(); o.end();
    o.end();
    o.begin(T_SEQUENCE);
    o.oid(OID_DATA);
    if (!detached) { o.begin(0xA0); o.octets(data); o.end(); }
    o.end();
    if (opt.with_cert) {
        Vec<Span> list;
        list.push(cert.der.span());
        for (size_t i = 0; i < opt.extra_n; ++i) list.push(opt.extra_certs[i]->der.span());
        for (size_t i = 0; i < list.n; ++i)
            for (size_t j = i + 1; j < list.n; ++j)
                if (cmp_span(list[j], list[i]) < 0) { Span t = list[i]; list[i] = list[j]; list[j] = t; }
        o.begin(0xA0);
        for (size_t i = 0; i < list.n; ++i) o.raw(list[i]);
        o.end();
    }
    o.begin(T_SET);
    o.raw(sp.signer_info.span());
    o.end();
    o.end();   // SignedData
    o.end();   // [0]
    o.end();   // ContentInfo
    if (!o.ok()) return false;
    return out.append(o.b.span());
}

bool cms_add_signer(Span existing_cms, const SignKey& key, Span detached_data, const CmsSignOptions& opt, Bytes& out) {
    if (!key.cert) return false;
    Bytes der;
    if (!ber_to_der(existing_cms, der)) return false;
    Span s = der.span();
    Tlv ci, oid, ex, sd;
    if (!der_expect(s, T_SEQUENCE, ci)) return false;
    Span in = ci.val;
    if (!der_expect(in, T_OID, oid) || !oid_is(oid.val, OID_SIGNED_DATA) || !der_expect(in, 0xA0, ex)) return false;
    Span exs = ex.val;
    if (!der_expect(exs, T_SEQUENCE, sd)) return false;
    Span sdin = sd.val;
    Tlv ver, digalgs, encap;
    if (!der_expect(sdin, T_INTEGER, ver) || !der_expect(sdin, T_SET, digalgs) || !der_expect(sdin, T_SEQUENCE, encap)) return false;

    // содержимое для хэша
    Bytes content;
    {
        Span ein = encap.val;
        Tlv ect;
        if (!der_expect(ein, T_OID, ect)) return false;
        if (ein.n) {
            Tlv e0, oc;
            if (!der_expect(ein, 0xA0, e0)) return false;
            Span e0s = e0.val;
            if (der_next(e0s, oc)) { if (!octets_join(oc, content)) return false; }
        } else if (!content.append(detached_data)) return false;
    }
    u8 dg[64];
    size_t dn;
    HashAlg alg;
    if (!hash_key_data(key, content.span(), dg, dn, alg)) return false;
    SignerParts sp;
    if (!build_signer_info(key, Span(dg, dn), opt.signing_time ? opt.signing_time : plat_unix_time(), sp)) return false;

    // digestAlgorithms: старые + новый (если ещё нет)
    Bytes new_alg;
    {
        DerOut a;
        a.begin(T_SEQUENCE); a.oid(sp.digest_oid); if (sp.gost) a.null(); a.end();
        new_alg = static_cast<Bytes&&>(a.b);
    }
    Vec<Span> algs;
    {
        Span as = digalgs.val;
        bool have = false;
        while (as.n) {
            Tlv t;
            if (!der_next(as, t)) return false;
            if (t.full().eq(new_alg.span())) have = true;
            algs.push(t.full());
        }
        if (!have) algs.push(new_alg.span());
    }
    Bytes algs_set;
    if (!der_set_of(algs, algs_set)) return false;

    // остальное: certificates [0], crls [1], signerInfos
    Bytes certs_part, crls_part, signers_set;
    Vec<Span> cert_list, signer_list;
    bool have_cert_field = false;
    while (sdin.n) {
        Tlv t;
        if (!der_next(sdin, t)) return false;
        if (t.tag == 0xA0) {
            have_cert_field = true;
            Span cs = t.val;
            while (cs.n) { Tlv c; if (!der_next(cs, c)) return false; cert_list.push(c.full()); }
        } else if (t.tag == 0xA1) {
            if (!crls_part.append(t.full())) return false;
        } else if (t.tag == T_SET) {
            Span ss = t.val;
            while (ss.n) { Tlv si; if (!der_next(ss, si)) return false; signer_list.push(si.full()); }
        }
    }
    if (opt.with_cert) {
        bool have = false;
        for (size_t i = 0; i < cert_list.n; ++i) if (cert_list[i].eq(key.cert->der.span())) have = true;
        if (!have) cert_list.push(key.cert->der.span());
        have_cert_field = true;
    }
    signer_list.push(sp.signer_info.span());
    if (!der_set_of(signer_list, signers_set)) return false;
    if (have_cert_field) {
        for (size_t i = 0; i < cert_list.n; ++i)
            for (size_t j = i + 1; j < cert_list.n; ++j)
                if (cmp_span(cert_list[j], cert_list[i]) < 0) { Span t = cert_list[i]; cert_list[i] = cert_list[j]; cert_list[j] = t; }
        Bytes cbody;
        for (size_t i = 0; i < cert_list.n; ++i) if (!cbody.append(cert_list[i])) return false;
        if (!der_wrap(0xA0, cbody.span(), certs_part)) return false;
    }

    DerOut o;
    o.begin(T_SEQUENCE);
    o.oid(OID_SIGNED_DATA);
    o.begin(0xA0);
    o.begin(T_SEQUENCE);
    o.raw(ver.full());
    o.raw(algs_set.span());
    o.raw(encap.full());
    if (certs_part.n) o.raw(certs_part.span());
    if (crls_part.n) o.raw(crls_part.span());
    o.raw(signers_set.span());
    o.end();
    o.end();
    o.end();
    if (!o.ok()) return false;
    return out.append(o.b.span());
}

}  // namespace nek
