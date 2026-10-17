// NEKalkan — чтение PKCS#12 (.p12/.pfx): ключ подписи ГОСТ 2015 / RSA и сертификаты.
#include "keystore.h"
#include "ciphers.h"
#include "gost3410.h"
#include "hash.h"

namespace nek {

void SignKey::reset() {
    gost_priv.reset();
    rsa.n.reset(); rsa.e.reset(); rsa.d.reset(); rsa.p.reset(); rsa.q.reset();
    rsa.dp.reset(); rsa.dq.reset(); rsa.qinv.reset();
    delete cert;
    cert = 0;
    for (size_t i = 0; i < others.n; ++i) delete others.d[i];
    others.n = 0;
    alias.reset();
    type = KEY_NONE;
    gost_size = 0;
}

static const u64 MAX_KDF_ITERS = 2000000;

static const char* const OID_SHROUDED_KEY = "1.2.840.113549.1.12.10.1.2";
static const char* const OID_KEY_BAG = "1.2.840.113549.1.12.10.1.1";
static const char* const OID_CERT_BAG = "1.2.840.113549.1.12.10.1.3";
static const char* const OID_X509_CERT = "1.2.840.113549.1.9.22.1";
static const char* const OID_FRIENDLY = "1.2.840.113549.1.9.20";

// ---- вспомогательное -----------------------------------------------------------------

static bool bmp_password(Span pw, Bytes& out) {
    Vec<u16> w;
    if (!utf8_to_utf16(pw, w)) return false;
    for (size_t i = 0; i < w.n; ++i)
        if (!out.push((u8)(w.d[i] >> 8)) || !out.push((u8)w.d[i])) return false;
    return out.push(0) && out.push(0);
}

// Содержимое OCTET STRING (простого или составного из кусков).
static bool octets_of(const Tlv& t, Bytes& out) {
    if (t.tag == T_OCTETSTRING || t.tag == 0x80) return out.append(t.val);
    if (t.tag == 0x24 || t.tag == 0xA0) {
        Span s = t.val;
        while (s.n) {
            Tlv c;
            if (!der_next(s, c)) return false;
            if (!octets_of(c, out)) return false;
        }
        return true;
    }
    return false;
}

static bool hash_by_name_oid(Span oid, HashAlg& h) {
    if (oid_is(oid, "1.3.14.3.2.26")) { h = H_SHA1; return true; }
    if (oid_is(oid, "2.16.840.1.101.3.4.2.1")) { h = H_SHA256; return true; }
    if (oid_is(oid, "2.16.840.1.101.3.4.2.2")) { h = H_SHA384; return true; }
    if (oid_is(oid, "2.16.840.1.101.3.4.2.3")) { h = H_SHA512; return true; }
    return false;
}

// ---- KDF PKCS#12 (RFC 7292, приложение B.2) ----------------------------------------------

static bool p12_kdf(HashAlg alg, Span pw_bmp, Span salt, u64 iters, u8 id, size_t n, Bytes& out) {
    size_t u = hash_size(alg), v = hash_block(alg);
    if (!u || !v || iters < 1 || iters > MAX_KDF_ITERS) return false;
    u8 D[128];
    for (size_t i = 0; i < v; ++i) D[i] = id;
    Bytes I;
    auto pad = [&](Span x) -> bool {
        if (!x.n) return true;
        size_t len = ((x.n + v - 1) / v) * v;
        for (size_t i = 0; i < len; ++i) if (!I.push(x.p[i % x.n])) return false;
        return true;
    };
    if (!pad(salt) || !pad(pw_bmp)) return false;
    size_t blocks = I.n / v;
    size_t rounds = (n + u - 1) / u;
    out.clear();
    for (size_t r = 0; r < rounds; ++r) {
        u8 A[64];
        HashCtx c;
        hash_init(c, alg);
        hash_update(c, D, v);
        hash_update(c, I.p, I.n);
        hash_final(c, A);
        for (u64 k = 1; k < iters; ++k) hash_data(alg, A, u, A);
        if (!out.append(A, u)) return false;
        if (r + 1 == rounds) break;
        u8 B[128];
        for (size_t i = 0; i < v; ++i) B[i] = A[i % u];
        for (size_t j = 0; j < blocks; ++j) {
            unsigned carry = 1;
            for (int k = (int)v - 1; k >= 0; --k) {
                unsigned t = I.p[j * v + k] + B[k] + carry;
                I.p[j * v + k] = (u8)t;
                carry = t >> 8;
            }
        }
    }
    out.n = n;
    out.p[n] = 0;
    return true;
}

static bool pbkdf2(HashAlg prf, Span pw, Span salt, u64 iters, size_t dklen, Bytes& out) {
    size_t hl = hash_size(prf);
    if (!hl || iters < 1 || iters > MAX_KDF_ITERS) return false;
    out.clear();
    for (u32 block = 1; out.n < dklen; ++block) {
        Bytes s;
        if (!s.append(salt)) return false;
        u8 ib[4] = {(u8)(block >> 24), (u8)(block >> 16), (u8)(block >> 8), (u8)block};
        if (!s.append(ib, 4)) return false;
        u8 U[64], T[64];
        hmac(prf, pw, s.span(), U);
        memcpy(T, U, hl);
        for (u64 i = 1; i < iters; ++i) {
            hmac(prf, pw, Span(U, hl), U);
            for (size_t k = 0; k < hl; ++k) T[k] ^= U[k];
        }
        if (!out.append(T, hl)) return false;
    }
    out.n = dklen;
    out.p[dklen] = 0;
    return true;
}

// ---- расшифрование PBE ----------------------------------------------------------------------

// params — TLV AlgorithmIdentifier.parameters. Возвращает KCR_OK / KCR_ERROR_READ_PKCS12 / KCR_INVALIDPASSWORD.
static u32 pbe_decrypt(Span alg_oid, Span params, Span ctext, Span pw_utf8, Span pw_bmp, Bytes& plain) {
    if (oid_is(alg_oid, "1.2.840.113549.1.5.13")) {            // PBES2
        Span ps = params;
        Tlv seq, kdf, enc;
        if (!der_expect(ps, T_SEQUENCE, seq)) return KCR_ERROR_READ_PKCS12;
        Span in = seq.val;
        if (!der_expect(in, T_SEQUENCE, kdf) || !der_expect(in, T_SEQUENCE, enc)) return KCR_ERROR_READ_PKCS12;
        Span ks = kdf.val, es = enc.val;
        Tlv ko, kp, eo, ei;
        if (!der_expect(ks, T_OID, ko) || !oid_is(ko.val, "1.2.840.113549.1.5.12")) return KCR_ERROR_READ_PKCS12;
        if (!der_expect(ks, T_SEQUENCE, kp)) return KCR_ERROR_READ_PKCS12;
        if (!der_expect(es, T_OID, eo) || !der_expect(es, T_OCTETSTRING, ei)) return KCR_ERROR_READ_PKCS12;
        Span kin = kp.val;
        Tlv salt, iter, x;
        if (!der_expect(kin, T_OCTETSTRING, salt) || !der_expect(kin, T_INTEGER, iter)) return KCR_ERROR_READ_PKCS12;
        u64 iters;
        if (!int_to_u64(iter.val, iters) || iters < 1 || iters > MAX_KDF_ITERS) return KCR_ERROR_READ_PKCS12;
        HashAlg prf = H_SHA1;
        if (kin.n && der_peek(kin, x) && x.tag == T_INTEGER) der_next(kin, x);       // keyLength — берём по шифру
        if (kin.n) {
            Tlv pa, po;
            if (!der_expect(kin, T_SEQUENCE, pa)) return KCR_ERROR_READ_PKCS12;
            Span pin = pa.val;
            if (!der_expect(pin, T_OID, po)) return KCR_ERROR_READ_PKCS12;
            if (oid_is(po.val, "1.2.840.113549.2.7")) prf = H_SHA1;
            else if (oid_is(po.val, "1.2.840.113549.2.9")) prf = H_SHA256;
            else if (oid_is(po.val, "1.2.840.113549.2.10")) prf = H_SHA384;
            else if (oid_is(po.val, "1.2.840.113549.2.11")) prf = H_SHA512;
            else return KCR_ERROR_READ_PKCS12;
        }
        size_t klen;
        int kind;                                   // 4 = AES, 2 = 3DES
        if (oid_is(eo.val, "2.16.840.1.101.3.4.1.2")) { klen = 16; kind = 4; }
        else if (oid_is(eo.val, "2.16.840.1.101.3.4.1.22")) { klen = 24; kind = 4; }
        else if (oid_is(eo.val, "2.16.840.1.101.3.4.1.42")) { klen = 32; kind = 4; }
        else if (oid_is(eo.val, "1.2.840.113549.3.7")) { klen = 24; kind = 2; }
        else return KCR_ERROR_READ_PKCS12;
        Bytes key;
        if (!pbkdf2(prf, pw_utf8, salt.val, iters, klen, key)) return KCR_ERROR_READ_PKCS12;
        if (ctext.n == 0 || ctext.n % (kind == 4 ? 16 : 8)) return KCR_ERROR_READ_PKCS12;
        if (!plain.resize(ctext.n)) return KCR_MEMORY_ERROR;
        bool ok = kind == 4 ? aes_cbc_decrypt(key.span(), ei.val, ctext, plain.p) : des3_cbc_decrypt(key.span(), ei.val, ctext, plain.p);
        if (!ok) return KCR_ERROR_READ_PKCS12;
        return pkcs7_unpad(plain, kind == 4 ? 16 : 8) ? KCR_OK : KCR_INVALIDPASSWORD;
    }

    // PKCS#12 PBE
    size_t klen = 0;
    int kind = 0, eff = 0;
    if (oid_is(alg_oid, "1.2.840.113549.1.12.1.3")) { kind = 2; klen = 24; }          // 3DES, 3 ключа
    else if (oid_is(alg_oid, "1.2.840.113549.1.12.1.4")) { kind = 5; klen = 16; }     // 3DES, 2 ключа
    else if (oid_is(alg_oid, "1.2.840.113549.1.12.1.5")) { kind = 3; klen = 16; eff = 128; }
    else if (oid_is(alg_oid, "1.2.840.113549.1.12.1.6")) { kind = 3; klen = 5; eff = 40; }
    else return KCR_ERROR_READ_PKCS12;
    Span ps = params;
    Tlv seq, salt, iter;
    if (!der_expect(ps, T_SEQUENCE, seq)) return KCR_ERROR_READ_PKCS12;
    Span in = seq.val;
    if (!der_expect(in, T_OCTETSTRING, salt) || !der_expect(in, T_INTEGER, iter)) return KCR_ERROR_READ_PKCS12;
    u64 iters;
    if (!int_to_u64(iter.val, iters) || iters < 1 || iters > MAX_KDF_ITERS) return KCR_ERROR_READ_PKCS12;
    Bytes key, iv;
    if (!p12_kdf(H_SHA1, pw_bmp, salt.val, iters, 1, klen, key) || !p12_kdf(H_SHA1, pw_bmp, salt.val, iters, 2, 8, iv))
        return KCR_ERROR_READ_PKCS12;
    if (ctext.n == 0 || ctext.n % 8) return KCR_ERROR_READ_PKCS12;
    if (!plain.resize(ctext.n)) return KCR_MEMORY_ERROR;
    bool ok;
    if (kind == 2) ok = des3_cbc_decrypt(key.span(), iv.span(), ctext, plain.p);
    else if (kind == 5) {
        u8 k24[24];
        memcpy(k24, key.p, 16); memcpy(k24 + 16, key.p, 8);
        ok = des3_cbc_decrypt(Span(k24, 24), iv.span(), ctext, plain.p);
    } else ok = rc2_cbc_decrypt(key.span(), eff, iv.span(), ctext, plain.p);
    if (!ok) return KCR_ERROR_READ_PKCS12;
    return pkcs7_unpad(plain, 8) ? KCR_OK : KCR_INVALIDPASSWORD;
}

// ---- проверка MAC ---------------------------------------------------------------------------------

static bool verify_mac(Span mac_data, Span authsafe, Span pw_bmp) {
    Span ms = mac_data;
    Tlv seq, di, salt, iter;
    if (!der_expect(ms, T_SEQUENCE, seq)) return false;
    Span in = seq.val;
    if (!der_expect(in, T_SEQUENCE, di) || !der_expect(in, T_OCTETSTRING, salt)) return false;
    u64 iters = 1;
    if (in.n && der_expect(in, T_INTEGER, iter) && !int_to_u64(iter.val, iters)) return false;
    Span dis = di.val;
    Tlv alg, digest, ao;
    if (!der_expect(dis, T_SEQUENCE, alg) || !der_expect(dis, T_OCTETSTRING, digest)) return false;
    Span as = alg.val;
    if (!der_expect(as, T_OID, ao)) return false;
    HashAlg h;
    if (!hash_by_name_oid(ao.val, h)) return false;
    if (iters < 1 || iters > MAX_KDF_ITERS) return false;
    Bytes key;
    if (!p12_kdf(h, pw_bmp, salt.val, iters, 3, hash_size(h), key)) return false;
    u8 mac[64];
    hmac(h, key.span(), authsafe, mac);
    return digest.val.n == hash_size(h) && ct_eq(mac, digest.val.p, digest.val.n);
}

// ---- разбор PrivateKeyInfo ---------------------------------------------------------------------------

// ищем в дереве OCTET STRING длиной 32/64 (ключ ГОСТ), включая вложенную обёртку 04 40 <key>
static bool find_gost_key(Span s, Bytes& out, int depth = 0) {
    if (depth > 8) return false;
    while (s.n) {
        Tlv t;
        if (!der_next(s, t)) return false;
        if (t.tag & 0x20) {
            if (find_gost_key(t.val, out, depth + 1)) return true;
        } else if (t.tag == T_OCTETSTRING && t.val.n) {
            if (t.val.n == 32 || t.val.n == 64) return out.assign(t.val);
            Span inner = t.val;
            Tlv x;
            if (der_peek(inner, x) && x.tag == T_OCTETSTRING && (x.val.n == 32 || x.val.n == 64) &&
                x.hdr.n + x.val.n == inner.n)
                return out.assign(x.val);
        }
    }
    return false;
}

struct KeyCandidate {
    KeyType type = KEY_NONE;
    bool legacy = false;     // ключ неподдерживаемого алгоритма (ГОСТ 34.10-2001/«2004», старые схемы НУЦ): подпись такими ключами не поддерживается
    Bytes gost;
    RsaPrivKey rsa;
};

static bool parse_private_key_info(Span plain_der, KeyCandidate& kc) {
    Span s = plain_der;
    Tlv seq;
    if (!der_expect(s, T_SEQUENCE, seq)) return false;
    Span in = seq.val;
    Tlv ver, alg, pk;
    if (!der_expect(in, T_INTEGER, ver) || !der_expect(in, T_SEQUENCE, alg) || !der_expect(in, T_OCTETSTRING, pk)) return false;
    Span as = alg.val;
    Tlv ao;
    if (!der_expect(as, T_OID, ao)) return false;
    if (oid_is(ao.val, OID_RSA_ENCRYPTION)) {
        Span ks = pk.val;
        Tlv rs;
        if (!der_expect(ks, T_SEQUENCE, rs)) return false;
        Span rin = rs.val;
        Tlv f[9];
        for (int i = 0; i < 9; ++i) if (!der_expect(rin, T_INTEGER, f[i])) return false;
        Bytes* dst[9] = {0, &kc.rsa.n, &kc.rsa.e, &kc.rsa.d, &kc.rsa.p, &kc.rsa.q, &kc.rsa.dp, &kc.rsa.dq, &kc.rsa.qinv};
        for (int i = 1; i < 9; ++i) if (!dst[i]->assign(int_magnitude(f[i].val))) return false;
        kc.type = KEY_RSA;
        return true;
    }
    {
        // распознаём только ГОСТ 34.10-2015 НУЦ РК (1.2.398.3.10.1.1.2.*); ключи ГОСТ 2001/«2004» и прочие старые схемы НУЦ
        // распознаются как неподдерживаемые для подписи (понятный код вместо «не читается контейнер»)
        char os[80];
        static const char kGost2015[] = "1.2.398.3.10.1.1.2.";
        if (!oid_to_str(ao.val, os, sizeof os) || !mem_eq(os, kGost2015, sizeof kGost2015 - 1)) { kc.legacy = true; return true; }
    }
    // ГОСТ: ключ ищем — любым OCTET STRING длины 32/64
    if (find_gost_key(seq.val, kc.gost)) { kc.type = KEY_GOST2015; return true; }
    return false;
}

static void reverse_bytes(Bytes& b) {
    for (size_t i = 0, j = b.n; i + 1 < j; ++i, --j) { u8 t = b.p[i]; b.p[i] = b.p[j - 1]; b.p[j - 1] = t; }
}

// Подходит ли ключ сертификату?
static bool gost_matches_cert(const Bytes& priv, const Cert& c) {
    if (!oid_is(c.spki_alg_oid, OID_KZ_GOST2015_KEY)) return false;
    Span point;
    if (!gost_point_from_spki_bits(c.spki_bits, point)) return false;
    size_t sz = priv.n;
    if (point.n != 2 * sz) return false;
    const GostCurve* cv = gost_curve((int)sz);
    if (!cv) return false;
    u8 pub_be[128];
    if (!gost3410_public_be(cv, priv.span(), pub_be)) return false;
    u8 pub_le[128];
    for (size_t i = 0; i < sz; ++i) { pub_le[i] = pub_be[sz - 1 - i]; pub_le[sz + i] = pub_be[2 * sz - 1 - i]; }
    return mem_eq(pub_le, point.p, 2 * sz);
}

static bool rsa_matches_cert(const RsaPrivKey& k, const Cert& c) {
    if (!oid_is(c.spki_alg_oid, OID_RSA_ENCRYPTION)) return false;
    Span s = c.spki_bits;
    Tlv seq, n;
    if (!der_expect(s, T_SEQUENCE, seq)) return false;
    Span in = seq.val;
    if (!der_expect(in, T_INTEGER, n)) return false;
    return int_magnitude(n.val).eq(int_magnitude(k.n.span()));
}

// ---- основной разбор ----------------------------------------------------------------------------------------

struct CertBag { Cert* cert; Bytes alias; };

static void get_friendly(Span attrs_set, Bytes& out) {
    // attrs_set — содержимое SET OF Attribute
    Span s = attrs_set;
    while (s.n) {
        Tlv a;
        if (!der_next(s, a) || a.tag != T_SEQUENCE) return;
        Span in = a.val;
        Tlv o, vs;
        if (!der_expect(in, T_OID, o) || !der_expect(in, T_SET, vs)) return;
        if (!oid_is(o.val, OID_FRIENDLY)) continue;
        Span v = vs.val;
        Tlv str;
        if (der_next(v, str)) { out.clear(); asn_string_to_utf8(str.tag, str.val, out); }
        return;
    }
}

static u32 process_safe_contents(Span sc_der, Span pw_bmp, Vec<KeyCandidate*>& keys, Vec<CertBag*>& certs, Span pw_utf8);

static u32 process_safe_bag(const Tlv& bag, Span pw_bmp, Span pw_utf8, Vec<KeyCandidate*>& keys, Vec<CertBag*>& certs) {
    Span in = bag.val;
    Tlv bid, bval;
    if (!der_expect(in, T_OID, bid) || !der_expect(in, 0xA0, bval)) return KCR_ERROR_READ_PKCS12;
    Bytes alias;
    if (in.n) {
        Tlv attrs;
        if (der_expect(in, T_SET, attrs)) get_friendly(attrs.val, alias);
    }
    Span vs = bval.val;
    if (oid_is(bid.val, OID_SHROUDED_KEY) || oid_is(bid.val, OID_KEY_BAG)) {
        Bytes plain;
        Span pkcs8;
        if (oid_is(bid.val, OID_SHROUDED_KEY)) {
            Tlv epki, alg, data, ao;
            if (!der_expect(vs, T_SEQUENCE, epki)) return KCR_ERROR_READ_PKCS12;
            Span ein = epki.val;
            if (!der_expect(ein, T_SEQUENCE, alg)) return KCR_ERROR_READ_PKCS12;
            Span ain = alg.val;
            if (!der_expect(ain, T_OID, ao)) return KCR_ERROR_READ_PKCS12;
            Span params = ain;                     // остаток алгоритма — параметры (TLV)
            Bytes ct;
            if (!der_next(ein, data) || !octets_of(data, ct)) return KCR_ERROR_READ_PKCS12;
            u32 rc = pbe_decrypt(ao.val, params, ct.span(), pw_utf8, pw_bmp, plain);
            if (rc) return rc;
            Bytes norm;
            if (!ber_to_der(plain.span(), norm)) return KCR_ERROR_READ_PKCS12;
            plain = static_cast<Bytes&&>(norm);
            pkcs8 = plain.span();
        } else {
            Tlv k;
            if (!der_peek(vs, k)) return KCR_ERROR_READ_PKCS12;
            pkcs8 = k.full();
        }
        KeyCandidate* kc = new KeyCandidate();
        if (!kc) return KCR_MEMORY_ERROR;
        if (!parse_private_key_info(pkcs8, *kc)) { delete kc; return KCR_ERROR_READ_PKCS12; }
        if (!keys.push(kc)) { delete kc; return KCR_MEMORY_ERROR; }
    } else if (oid_is(bid.val, OID_CERT_BAG)) {
        Tlv cb, cid, cval;
        if (!der_expect(vs, T_SEQUENCE, cb)) return KCR_ERROR_READ_PKCS12;
        Span cin = cb.val;
        if (!der_expect(cin, T_OID, cid) || !der_expect(cin, 0xA0, cval)) return KCR_ERROR_READ_PKCS12;
        if (!oid_is(cid.val, OID_X509_CERT)) return KCR_OK;
        Span vv = cval.val;
        Tlv oct;
        Bytes der;
        if (!der_next(vv, oct) || !octets_of(oct, der)) return KCR_ERROR_READ_PKCS12;
        CertBag* cbag = new CertBag();
        if (!cbag) return KCR_MEMORY_ERROR;
        cbag->cert = new Cert();
        if (!cbag->cert) { delete cbag; return KCR_MEMORY_ERROR; }
        if (!cbag->cert->load(der.span())) { delete cbag->cert; delete cbag; return KCR_ERROR_READ_PKCS12; }
        cbag->alias = static_cast<Bytes&&>(alias);
        if (!certs.push(cbag)) { delete cbag->cert; delete cbag; return KCR_MEMORY_ERROR; }
    }
    return KCR_OK;
}

static u32 process_safe_contents(Span sc, Span pw_bmp, Vec<KeyCandidate*>& keys, Vec<CertBag*>& certs, Span pw_utf8) {
    Span s = sc;
    Tlv seq;
    if (!der_expect(s, T_SEQUENCE, seq)) return KCR_ERROR_READ_PKCS12;
    Span in = seq.val;
    while (in.n) {
        Tlv bag;
        if (!der_next(in, bag) || bag.tag != T_SEQUENCE) return KCR_ERROR_READ_PKCS12;
        u32 rc = process_safe_bag(bag, pw_bmp, pw_utf8, keys, certs);
        if (rc) return rc;
    }
    return KCR_OK;
}

u32 p12_load(Span data, Span password, SignKey& out) {
    out.reset();
    Bytes der;
    if (!ber_to_der(data, der)) return KCR_ERROR_READ_PKCS12;
    Bytes pw_bmp;
    if (!bmp_password(password, pw_bmp)) return KCR_INVALIDPASSWORD;

    Span s = der.span();
    Tlv pfx, ver, authsafe;
    if (!der_expect(s, T_SEQUENCE, pfx)) return KCR_ERROR_READ_PKCS12;
    Span in = pfx.val;
    if (!der_expect(in, T_INTEGER, ver) || !der_expect(in, T_SEQUENCE, authsafe)) return KCR_ERROR_READ_PKCS12;
    Span as = authsafe.val;
    Tlv aoid, aval;
    if (!der_expect(as, T_OID, aoid) || !oid_is(aoid.val, "1.2.840.113549.1.7.1") || !der_expect(as, 0xA0, aval))
        return KCR_ERROR_READ_PKCS12;
    Span avs = aval.val;
    Tlv aoct;
    Bytes authsafe_content;
    if (!der_next(avs, aoct) || !octets_of(aoct, authsafe_content)) return KCR_ERROR_READ_PKCS12;

    {
        // MAC обязателен (как у OpenSSL/KalkanCrypt): без него целостность контейнера и пароль не подтверждены
        Tlv macd;
        if (!in.n || !der_peek(in, macd) || macd.tag != T_SEQUENCE) return KCR_ERROR_READ_PKCS12;
        if (!verify_mac(macd.full(), authsafe_content.span(), pw_bmp.span())) return KCR_INVALIDPASSWORD;
    }

    Vec<KeyCandidate*> keys;
    Vec<CertBag*> certs;
    u32 rc = KCR_OK;
    {
        Bytes as_norm;
        if (!ber_to_der(authsafe_content.span(), as_norm)) rc = KCR_ERROR_READ_PKCS12;
        else {
            Span a = as_norm.span();
            Tlv aseq;
            if (!der_expect(a, T_SEQUENCE, aseq)) rc = KCR_ERROR_READ_PKCS12;
            else {
                Span ci = aseq.val;
                while (ci.n && rc == KCR_OK) {
                    Tlv c;
                    if (!der_next(ci, c) || c.tag != T_SEQUENCE) { rc = KCR_ERROR_READ_PKCS12; break; }
                    Span cin = c.val;
                    Tlv coid, cval;
                    if (!der_expect(cin, T_OID, coid) || !der_expect(cin, 0xA0, cval)) { rc = KCR_ERROR_READ_PKCS12; break; }
                    Span cv = cval.val;
                    if (oid_is(coid.val, "1.2.840.113549.1.7.1")) {
                        Tlv oct;
                        Bytes sc, scn;
                        if (!der_next(cv, oct) || !octets_of(oct, sc) || !ber_to_der(sc.span(), scn)) { rc = KCR_ERROR_READ_PKCS12; break; }
                        rc = process_safe_contents(scn.span(), pw_bmp.span(), keys, certs, password);
                    } else if (oid_is(coid.val, "1.2.840.113549.1.7.6")) {
                        Tlv ed, eci, alg, ao;
                        if (!der_expect(cv, T_SEQUENCE, ed)) { rc = KCR_ERROR_READ_PKCS12; break; }
                        Span edn = ed.val;
                        Tlv evv;
                        if (!der_expect(edn, T_INTEGER, evv) || !der_expect(edn, T_SEQUENCE, eci)) { rc = KCR_ERROR_READ_PKCS12; break; }
                        Span ein = eci.val;
                        Tlv ctype;
                        if (!der_expect(ein, T_OID, ctype) || !der_expect(ein, T_SEQUENCE, alg)) { rc = KCR_ERROR_READ_PKCS12; break; }
                        Span ain = alg.val;
                        if (!der_expect(ain, T_OID, ao)) { rc = KCR_ERROR_READ_PKCS12; break; }
                        Span params = ain;
                        Tlv ec;
                        Bytes ct, plain, norm;
                        if (!der_next(ein, ec) || !octets_of(ec, ct)) { rc = KCR_ERROR_READ_PKCS12; break; }
                        rc = pbe_decrypt(ao.val, params, ct.span(), password, pw_bmp.span(), plain);
                        if (rc) break;
                        if (!ber_to_der(plain.span(), norm)) { rc = KCR_ERROR_READ_PKCS12; break; }
                        rc = process_safe_contents(norm.span(), pw_bmp.span(), keys, certs, password);
                    }
                }
            }
        }
    }

    if (rc == KCR_OK) {
        // подобрать пару «ключ + сертификат»
        bool found = false;
        for (size_t ki = 0; ki < keys.n && !found; ++ki) {
            KeyCandidate& kc = *keys.d[ki];
            if (kc.legacy) continue;
            for (int attempt = 0; attempt < (kc.type == KEY_GOST2015 ? 2 : 1) && !found; ++attempt) {
                if (attempt == 1) reverse_bytes(kc.gost);
                for (size_t ci = 0; ci < certs.n && !found; ++ci) {
                    bool ok = kc.type == KEY_GOST2015 ? gost_matches_cert(kc.gost, *certs.d[ci]->cert)
                                                      : rsa_matches_cert(kc.rsa, *certs.d[ci]->cert);
                    if (!ok) continue;
                    found = true;
                    out.type = kc.type;
                    if (kc.type == KEY_GOST2015) {
                        out.gost_size = (int)kc.gost.n;
                        out.gost_priv = static_cast<Bytes&&>(kc.gost);
                    } else {
                        out.rsa.n = static_cast<Bytes&&>(kc.rsa.n); out.rsa.e = static_cast<Bytes&&>(kc.rsa.e);
                        out.rsa.d = static_cast<Bytes&&>(kc.rsa.d); out.rsa.p = static_cast<Bytes&&>(kc.rsa.p);
                        out.rsa.q = static_cast<Bytes&&>(kc.rsa.q); out.rsa.dp = static_cast<Bytes&&>(kc.rsa.dp);
                        out.rsa.dq = static_cast<Bytes&&>(kc.rsa.dq); out.rsa.qinv = static_cast<Bytes&&>(kc.rsa.qinv);
                    }
                    out.cert = certs.d[ci]->cert;
                    certs.d[ci]->cert = 0;
                    out.alias = static_cast<Bytes&&>(certs.d[ci]->alias);
                }
            }
        }
        bool legacy_only = false;
        for (size_t ki = 0; ki < keys.n; ++ki) if (keys.d[ki]->legacy) legacy_only = true;
        if (!found) rc = legacy_only ? KCR_UNKNOWN_ALG : (keys.n ? KCR_CERTNOTFOUND : KCR_KEY_NOT_FOUND);
        if (found)
            for (size_t ci = 0; ci < certs.n; ++ci)
                if (certs.d[ci]->cert) { out.others.push(certs.d[ci]->cert); certs.d[ci]->cert = 0; }
    }
    for (size_t i = 0; i < keys.n; ++i) delete keys.d[i];
    for (size_t i = 0; i < certs.n; ++i) { delete certs.d[i]->cert; delete certs.d[i]; }
    return rc;
}

}  // namespace nek
