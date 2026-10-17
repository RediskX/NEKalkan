// NEKalkan — совместимость с KalkanCrypt: реализация.
#include "kalkan.h"
#include "asn1.h"
#include "certprop.h"
#include "cms.h"
#include "codec.h"
#include "crl.h"
#include "hash.h"
#include "legacy.h"
#include "plat.h"
#include "xmldsig.h"

namespace nek {

enum : u32 {
    KCR_CADESBES_FAILED = KCR_BASE + 0x48,
    KCR_NOTSATOKEN_ = KCR_BASE + 0x4a,
    KCR_CRLEXPIRED = KCR_BASE + 0x5d,
    KCR_TSACREATEQUERY = KCR_BASE + 0x44,
};

static const char* const kPemCms = "CMS";

// ---- служебное ----------------------------------------------------------------------------------

static void put_hex(Bytes& b, u32 v) {
    char tmp[12];
    int k = 0;
    if (!v) tmp[k++] = '0';
    while (v) { tmp[k++] = "0123456789abcdef"[v & 15]; v >>= 4; }
    b.append_str("0x");
    while (k) b.push((u8)tmp[--k]);
}

static void put_dec(Bytes& b, u64 v) {
    char tmp[24];
    int k = 0;
    if (!v) tmp[k++] = '0';
    while (v) { tmp[k++] = (char)('0' + v % 10); v /= 10; }
    while (k) b.push((u8)tmp[--k]);
}

Kalkan::Kalkan() {}
Kalkan::~Kalkan() { clear_certs(); }

void Kalkan::clear_certs() {
    for (size_t i = 0; i < ca_.n; ++i) delete ca_.d[i];
    for (size_t i = 0; i < inter_.n; ++i) delete inter_.d[i];
    for (size_t i = 0; i < user_.n; ++i) delete user_.d[i];
    ca_.n = inter_.n = user_.n = 0;
}

u32 Kalkan::fail(u32 code, const char* op, const char* text) {
    last_code_ = code;
    log_.append_str("ERROR ");
    put_hex(log_, code);
    log_.append_str(": ");
    log_.append_str(op);
    log_.append_str(" - ");
    log_.append_str(text);
    log_.append_str(".\r\n");
    return code;
}

void Kalkan::note(const char* op, const char* text) {
    log_.append_str(op);
    log_.append_str(" - ");
    log_.append_str(text);
    log_.append_str(".\r\n");
}

u32 Kalkan::Init() {
    inited_ = true;
    last_code_ = 0;
    return KCR_OK;
}

void Kalkan::Finalize() {
    key_.reset();
    has_key_ = false;
    clear_certs();
    inited_ = false;
    last_code_ = 0;
    log_.clear();
}

// ---- разбор входов и кодирование выходов -------------------------------------------------------------

bool Kalkan::parse_cert(Span in, Cert& c) {
    Bytes raw;
    if (looks_like_pem(in)) {
        if (!pem_decode(in, raw)) return false;
    } else if (in.n && in.p[0] == 0x30) {
        if (!raw.append(in)) return false;
    } else if (!b64_decode(in, raw)) return false;
    return c.load(raw.span());
}

// Данные из текста по флагам: IN_FILE — путь, IN_PEM/IN_BASE64 — декодирование.
u32 Kalkan::decode_input(Span in, u32 flags, bool is_signature, Bytes& out, const char* op) {
    Bytes raw;
    if (flags & KC_IN_FILE) {
        Bytes path;
        path.append(in);
        if (!plat_read_file(path.cstr(), raw)) {
            fail(KCR_OPENFILEERR, "Reading file", "unable to open file");
            return fail(KCR_OPENFILEERR, op, "unable to open file");
        }
    } else if (!raw.append(in)) return fail(KCR_MEMORY_ERROR, op, "memory error");
    out.clear();
    bool pem = (flags & KC_IN_PEM) != 0;
    if (!pem && is_signature && !(flags & (KC_IN_BASE64 | KC_IN_DER)) && looks_like_pem(raw.span())) pem = true;
    if (pem && is_signature) {
        if (!pem_decode(raw.span(), out)) return fail(KCR_BASE64_DECODE_ERROR, op, "decode error");
        return KCR_OK;
    }
    bool b64 = is_signature ? (flags & KC_IN_BASE64) != 0 : (flags & KC_IN_BASE64) != 0;
    if (b64) {
        if (!b64_decode_strict(raw.span(), out)) return fail(KCR_BASE64_DECODE_ERROR, op, "decode error");
        return KCR_OK;
    }
    if (!out.append(raw.span())) return fail(KCR_MEMORY_ERROR, op, "memory error");
    return KCR_OK;
}

void Kalkan::encode_out(Span data, u32 flags, bool is_cms, Bytes& out) {
    out.clear();
    if (flags & KC_OUT_BASE64) { b64_encode(data, out, 0); return; }
    if (is_cms && (flags & KC_OUT_PEM)) {
        out.append_str("-----BEGIN ");
        out.append_str(kPemCms);
        out.append_str("-----\n");
        b64_encode(data, out, 64, "\n");
        out.append_str("\n-----END ");
        out.append_str(kPemCms);
        out.append_str("-----");
        return;
    }
    out.append(data);
}

u32 Kalkan::encode_cert(const Cert& c, u32 f, Bytes& out) {
    out.clear();
    if (f & KC_OUT_DER) return out.append(c.der.span()) ? KCR_OK : KCR_MEMORY_ERROR;
    if (f & KC_OUT_BASE64) return b64_encode(c.der.span(), out, 64, "\n") ? KCR_OK : KCR_MEMORY_ERROR;
    return pem_encode(c.der.span(), "CERTIFICATE", out) ? KCR_OK : KCR_MEMORY_ERROR;
}

// ---- хранилище ключей --------------------------------------------------------------------------------

u32 Kalkan::LoadKeyStore(u32 storage, Span password, Span container, Span alias) {
    (void)alias;
    if (!inited_) return fail(KCR_LIBRARYNOTINITIALIZED, "Load key store", "library not initialized");
    if (storage != KCST_PKCS12) return fail(KCR_NOTOKENFOUND, "Load key store", "token not found");
    Bytes path, data;
    if (!path.append(container)) return fail(KCR_MEMORY_ERROR, "Load key store", "memory error");
    if (!plat_read_file(path.cstr(), data)) return fail(KCR_ERROR_OPEN_PKCS12, "Load key store", "unable to open file");
    SignKey k;
    u32 rc = p12_load(data.span(), password, k);
    if (rc == KCR_INVALIDPASSWORD) return fail(rc, "Load key store", "invalid password");
    if (rc) return fail(rc, "Load key store", rc == KCR_KEY_NOT_FOUND ? "private key not found" : rc == KCR_UNKNOWN_ALG ? "private key algorithm is not supported (only GOST 34.10-2015 and RSA)" : "unable to read PKCS#12");
    key_.reset();
    key_.type = k.type;
    key_.gost_size = k.gost_size;
    key_.gost_priv = static_cast<Bytes&&>(k.gost_priv);
    key_.rsa.n = static_cast<Bytes&&>(k.rsa.n); key_.rsa.e = static_cast<Bytes&&>(k.rsa.e); key_.rsa.d = static_cast<Bytes&&>(k.rsa.d);
    key_.rsa.p = static_cast<Bytes&&>(k.rsa.p); key_.rsa.q = static_cast<Bytes&&>(k.rsa.q); key_.rsa.dp = static_cast<Bytes&&>(k.rsa.dp);
    key_.rsa.dq = static_cast<Bytes&&>(k.rsa.dq); key_.rsa.qinv = static_cast<Bytes&&>(k.rsa.qinv);
    key_.cert = k.cert; k.cert = 0;
    for (size_t i = 0; i < k.others.n; ++i) key_.others.push(k.others.d[i]);
    k.others.n = 0;
    key_.alias = static_cast<Bytes&&>(k.alias);
    has_key_ = true;
    note("Load key store");
    return KCR_OK;
}

u32 Kalkan::LoadCertFromFile(Span path, u32 cert_type) {
    if (!inited_) return fail(KCR_LIBRARYNOTINITIALIZED, "X509 Load certificate from file", "library not initialized");
    Bytes p, data;
    p.append(path);
    if (!plat_read_file(p.cstr(), data)) return fail(KCR_OPENFILEERR, "X509 Load certificate from file", "unable to open file");
    return LoadCertFromBuffer(data.span(), cert_type);
}

u32 Kalkan::LoadCertFromBuffer(Span data, u32 flag) {
    if (!inited_) return fail(KCR_LIBRARYNOTINITIALIZED, "X509 Load certificate from buffer", "library not initialized");
    Cert* c = new Cert();
    if (!c) return fail(KCR_MEMORY_ERROR, "X509 Load certificate", "memory error");
    if (!parse_cert(data, *c)) {
        delete c;
        fail(KCR_CERT_PARSE_ERROR, "X509 Load certificate from buffer", "unable to parse certificate");
        return fail(KCR_CERTNOTFOUND, "X509 Load certificate from buffer", "failed to load certificate");
    }
    u32 type = flag & 0x20F;
    Vec<Cert*>* dst = &user_;
    if ((type & 0x2FF) == KC_CERT_CA) dst = &ca_;
    else if ((type & 0x2FF) == KC_CERT_INTERMEDIATE) dst = &inter_;
    for (size_t i = 0; i < dst->n; ++i)
        if (dst->d[i]->der.span().eq(c->der.span())) { delete c; note("X509 Load certificate"); return KCR_OK; }
    dst->push(c);
    note("X509 Load certificate");
    return KCR_OK;
}

u32 Kalkan::ExportCert(Span alias, u32 flag, Bytes& out) {
    (void)alias;
    if (!inited_) return fail(KCR_LIBRARYNOTINITIALIZED, "X509 Export certificate from store", "library not initialized");
    if (!has_key_ || !key_.cert) return fail(KCR_CERTNOTFOUND, "X509 Export certificate from store", "certificate not found");
    u32 rc = encode_cert(*key_.cert, flag, out);
    if (rc) return fail(rc, "X509 Export certificate from store", "memory error");
    note("X509 Export certificate from store");
    return KCR_OK;
}

u32 Kalkan::CertGetInfo(Span cert, u32 prop_id, Bytes& out) {
    out.clear();
    if (!inited_) return fail(KCR_LIBRARYNOTINITIALIZED, "Get PKI data properties", "library not initialized");
    Cert c;
    if (!parse_cert(cert, c)) return fail(KCR_CERT_PARSE_ERROR, "Get PKI data properties", "unable to parse certificate");
    u32 rc = cert_get_info(c, prop_id, out);
    if (rc == KCR_INVALID_PROPID) return fail(rc, "Get PKI data properties", "invalid propID");
    if (rc) return fail(rc, "Get PKI data properties", "error");
    // как у KalkanCrypt: отсутствующий атрибут имени (страна, область, e-mail, подразделение …) — ошибка, а не пустое значение
    if (!out.n && prop_id >= KC_CERTPROP_ISSUER_COUNTRYNAME && prop_id <= KC_CERTPROP_SUBJECT_DC)
        return fail(KCR_GETCERTPROPERR, "Get PKI data properties", "certificate attribute not found");
    return KCR_OK;
}

u32 Kalkan::chain_check(const Cert& c, u32 flags) {
    // как у KalkanCrypt: прежде всего в хранилище (корневые + промежуточные) должен найтись издатель сертификата
    bool known = false;
    for (size_t i = 0; i < ca_.n && !known; ++i) known = ca_.d[i]->subject.eq(c.issuer);
    for (size_t i = 0; i < inter_.n && !known; ++i) known = inter_.d[i]->subject.eq(c.issuer);
    if (!known) {
        fail(KCR_CACERTNOTFOUND, "Load certificate from system store", "not found root or intermediate certificate in system store");
        return KCR_CACERTNOTFOUND;
    }
    Vec<const Cert*> pool;
    for (size_t i = 0; i < inter_.n; ++i) pool.push(inter_.d[i]);
    for (size_t i = 0; i < key_.others.n; ++i) pool.push(key_.others.d[i]);
    for (size_t i = 0; i < user_.n; ++i) pool.push(user_.d[i]);
    Vec<const Cert*> anchors;
    for (size_t i = 0; i < ca_.n; ++i) anchors.push(ca_.d[i]);
    u32 rc = chain_validate(c, pool.d, pool.n, anchors.d, anchors.n, 0, (flags & KC_NOCHECKCERTTIME) ? CHAIN_NO_TIME : 0);
    if (rc == KCR_CERTTIMEINVALID) fail(rc, "Verify chain and certificates:", "certificate has expired or is not yet valid");
    else if (rc) {
        // издатель найден, но цепочка до доверенного корня не выстроилась (KalkanCrypt в подписи/проверке данных
        // здесь пропускает; NEKalkan намеренно строже и требует корневой сертификат)
        rc = KCR_CHECKCHAINERROR;
        fail(rc, "Verify chain and certificates:", "CA certificate not found or chain is invalid");
    }
    return rc;
}

u32 Kalkan::check_signer(const SignKey& k, u32 flags, bool need_chain) {
    if (!k.cert) return KCR_CERTNOTFOUND;
    i64 now = plat_unix_time();
    if (!(flags & KC_NOCHECKCERTTIME) && (now < k.cert->not_before || now > k.cert->not_after))
        return fail(KCR_CERTTIMEINVALID, "Verify chain and certificates:", "certificate has expired or is not yet valid");
    if (need_chain) return chain_check(*k.cert, flags);
    return KCR_OK;
}

u32 Kalkan::ValidateCert(Span cert, u32 valid_type, Span valid_path, i64 check_time, u32 flags, Bytes& info, Bytes& ocsp) {
    (void)check_time;   // зарезервировано (как у KalkanCrypt)
    info.clear();
    ocsp.clear();
    if (!inited_) return fail(KCR_LIBRARYNOTINITIALIZED, "Verify chain and certificates:", "library not initialized");
    Cert c;
    if (!parse_cert(cert, c)) return fail(KCR_CERT_PARSE_ERROR, "Verify chain and certificates:", "unable to parse certificate");
    if (valid_type != KC_USE_NOTHING && valid_type != KC_USE_CRL && valid_type != KC_USE_OCSP) {
        last_code_ = KCR_VALIDTYPEERROR;
        return KCR_VALIDTYPEERROR;
    }
    u32 rc = chain_check(c, flags);
    if (rc) return rc;
    if (valid_type == KC_USE_CRL) {
        Bytes p, data;
        p.append(valid_path);
        if (!plat_read_file(p.cstr(), data)) return fail(KCR_LOADCRLERROR, "Load CRL", "unable to load CRL (only local files are supported)");
        Crl crl;
        if (!crl.load(data.span())) return fail(KCR_BADCRLFORMAT, "Load CRL", "bad CRL format");
        const Cert* issuer = 0;
        for (size_t i = 0; i < ca_.n && !issuer; ++i) if (ca_.d[i]->subject.eq(c.issuer)) issuer = ca_.d[i];
        for (size_t i = 0; i < inter_.n && !issuer; ++i) if (inter_.d[i]->subject.eq(c.issuer)) issuer = inter_.d[i];
        if (!issuer || !crl.verify(*issuer)) return fail(KCR_LOADCRLERROR, "Verify CRL", "CRL was not issued by the certificate issuer or its signature is invalid");
        if (crl.is_delta) { /* delta-CRL: проверяем только серийный номер */ }
        i64 now = plat_unix_time();
        if (crl.has_next && now > crl.next_update) return fail(KCR_CRLEXPIRED, "Verify CRL", "CRL has expired");
        if (crl.is_revoked(c.serial)) return fail(KCR_CERT_STATUS_REVOKED, "Verify certificate status", "certificate is revoked");
        info.append_str("Verify chain and certificates: - OK.\nCRL status - OK.");
        note("Verify certificate status");
        return KCR_OK;
    }
    if (valid_type == KC_USE_OCSP) {
        return fail(KCR_OCSP_CONNECTIONERR, "OCSP", "online certificate status check is not available in this build");
    }
    info.append_str("Verify chain and certificates: - OK.");
    note("Verify chain and certificates:");
    return KCR_OK;
}

u32 Kalkan::GetCertificatesList(Bytes& out, u32& count) {
    out.clear();
    count = 0;
    if (!has_key_ || !key_.cert) return fail(KCR_CERTNOTFOUND, "Get certificates list", "certificate not found");
    count = 1;
    if (key_.alias.n) out.append(key_.alias.span());
    else {
        Bytes cn;
        name_get(key_.cert->subject, "2.5.4.3", cn);
        out.append(cn.span());
    }
    return KCR_OK;
}

u32 Kalkan::GetTokens(u32 storage, Bytes& out, u32& count) {
    (void)storage;
    out.clear();
    count = 0;
    return fail(KCR_NOTOKENFOUND, "Get tokens", "token not found");
}

// ---- хэш ----------------------------------------------------------------------------------------------

static bool ieq(Span s, const char* c) {
    size_t n = cstrlen(c);
    if (s.n != n) return false;
    for (size_t i = 0; i < n; ++i) {
        u8 a = s.p[i], b = (u8)c[i];
        if (a >= 'A' && a <= 'Z') a += 32;
        if (b >= 'A' && b <= 'Z') b += 32;
        if (a != b) return false;
    }
    return true;
}

u32 Kalkan::HashData(Span algorithm, u32 flags, Span in, Bytes& out) {
    out.clear();
    if (!inited_) return fail(KCR_LIBRARYNOTINITIALIZED, "Hash data", "library not initialized");
    HashAlg a = H_NONE;
    if (flags & KC_HASH_GOST15_512) a = H_STREEBOG512;
    else if (flags & KC_HASH_GOST15_256) a = H_STREEBOG256;
    else if (flags & KC_HASH_GOST95) a = H_GOST94;
    else if (flags & KC_HASH_SHA256) a = H_SHA256;
    else if (ieq(algorithm, "sha256")) a = H_SHA256;
    else if (ieq(algorithm, "Gost34311_95")) a = H_GOST94;
    if (a == H_NONE) return fail(KCR_UNKNOWN_ALG, "Hash data", "unknown algorithm");
    Bytes data;
    u32 rc = decode_input(in, flags & (KC_IN_FILE | KC_IN_BASE64), false, data, "Hash data");
    if (rc) return rc;
    u8 h[64];
    hash_data(a, data.span(), h);
    Bytes res;
    res.append(h, hash_size(a));
    if (flags & KC_OUT_BASE64) b64_encode(res.span(), out, 0);
    else out.append(res.span());
    note("Hash data");
    return KCR_OK;
}

// ---- подпись ----------------------------------------------------------------------------------------------

u32 Kalkan::SignHash(Span alias, u32 flags, Span hash, Bytes& out) {
    (void)alias;
    out.clear();
    if (!inited_) return fail(KCR_LIBRARYNOTINITIALIZED, "Sign hash", "library not initialized");
    if (!has_key_) return fail(KCR_KEY_NOT_FOUND, "Sign hash", "private key not found");
    bool cms = (flags & KC_SIGN_CMS) && !(flags & KC_SIGN_DRAFT);
    if (!(flags & (KC_SIGN_DRAFT | KC_SIGN_CMS))) return fail(KCR_INVALID_FLAGS, "Sign hash", "invalid flags");
    Bytes h;
    if (flags & KC_IN_BASE64) {
        if (!b64_decode_strict(hash, h)) return fail(KCR_BASE64_DECODE_ERROR, "Sign hash", "decode error");
    } else h.append(hash);
    size_t want = key_.type == KEY_GOST2015 ? (size_t)key_.gost_size : 32;
    if (h.n != want) return fail(KCR_INVALID_DIGEST_LEN, "Sign hash", "invalid digest length");
    if (cms) {
        u32 rc = check_signer(key_, flags, false);       // как у KalkanCrypt: SignHash не требует загруженных УЦ
        if (rc) return rc;
        CmsSignOptions o;
        o.precomputed_digest = h.span();
        Bytes der;
        if (!cms_sign(key_, Span(), o, der)) return fail(KCR_SIGNHASH_ERROR, "Sign hash", "unable to sign hash");
        encode_out(der.span(), flags, true, out);
        note("Sign hash");
        return KCR_OK;
    }
    Bytes sig;
    if (!sign_prehashed(key_, h.span(), sig)) return fail(KCR_SIGNHASH_ERROR, "Sign hash", "unable to sign hash");
    encode_out(sig.span(), flags, false, out);
    note("Sign hash");
    return KCR_OK;
}

u32 Kalkan::SignData(Span alias, u32 flags, Span in, Span in_sign, Bytes& out) {
    (void)alias;
    out.clear();
    if (!inited_) return fail(KCR_LIBRARYNOTINITIALIZED, "Sign data", "library not initialized");
    if (!flags) return fail(KCR_INVALID_FLAGS, "Sign Data", "invalid flags");
    if (!(flags & (KC_SIGN_DRAFT | KC_SIGN_CMS))) return fail(KCR_SIGNFORMMAT, "Sign Data", "unknown sign format");
    if (!has_key_ || !key_.cert) return fail(KCR_KEY_NOT_FOUND, "Sign Data", "private key not found");
    Bytes data;
    u32 rc = decode_input(in, flags & (KC_IN_FILE | KC_IN_BASE64), false, data, "Sign Data");
    if (rc) return rc;
    bool raw = (flags & KC_SIGN_DRAFT) != 0;
    rc = check_signer(key_, flags, true);          // как у KalkanCrypt: цепочка проверяется и для RAW
    if (rc) return rc;
    if (raw) {
        Bytes sig;
        if (!raw_sign(key_, data.span(), sig)) return fail(KCR_SIGN_ERROR, "Sign Data", "unable to generate signature");
        encode_out(sig.span(), flags, false, out);
        note("Sign Data");
        return KCR_OK;
    }
    if (flags & KC_WITH_TIMESTAMP) return fail(KCR_HTTPERROR, "Sign Data", "timestamp (TSA) requests are not available in this build");
    CmsSignOptions o;
    o.detached = (flags & KC_DETACHED_DATA) != 0;
    o.with_cert = true;
    Bytes der;
    if (in_sign.n) {
        Bytes existing;
        rc = decode_input(in_sign, (flags & (KC_IN_PEM | KC_IN_BASE64 | KC_IN_DER)) | ((flags & KC_IN2_BASE64) ? KC_IN_BASE64 : 0), true, existing, "Sign Data");
        if (rc) return rc;
        if (!cms_add_signer(existing.span(), key_, data.span(), o, der)) return fail(KCR_SIGN_ERROR, "Sign Data", "unable to add signature");
    } else if (!cms_sign(key_, data.span(), o, der)) return fail(KCR_SIGN_ERROR, "Sign Data", "unable to generate signature");
    encode_out(der.span(), flags, true, out);
    note("Sign Data");
    return KCR_OK;
}

// ---- проверка подписи --------------------------------------------------------------------------------------------

u32 Kalkan::VerifyData(Span alias, u32 flags, Span in_data, Span in_sign, int cert_id, Bytes& out_data, Bytes& info, Bytes& out_cert) {
    (void)alias;
    out_data.clear(); info.clear(); out_cert.clear();
    if (!inited_) return fail(KCR_LIBRARYNOTINITIALIZED, "Verify Data", "library not initialized");
    if (!(flags & (KC_SIGN_DRAFT | KC_SIGN_CMS))) return fail(KCR_SIGNFORMMAT, "Verify Data", "unknown sign format");
    Bytes sig;
    u32 rc = decode_input(in_sign, flags & (KC_IN_FILE | KC_IN_PEM | KC_IN_BASE64 | KC_IN_DER), true, sig, "Verify Data");
    if (rc) return rc;
    // подписанные данные (RAW / detached CMS)
    // Как у KalkanCrypt: для CMS данные берутся из параметра только с флагом DETACHED (и тогда проверяются именно они, даже если CMS содержит свои);
    // без флага используется вложенное содержимое, а параметр игнорируется.
    Bytes data;
    const bool det = (flags & KC_DETACHED_DATA) != 0;
    if (!(flags & KC_SIGN_DRAFT) && det && !in_data.n) return fail(KCR_VERIFY_NODATA, "Verify Data", "no input data for detached CMS signature");
    if ((flags & KC_SIGN_DRAFT) || det) {
        if (flags & KC_IN2_BASE64) {
            if (!b64_decode_strict(in_data, data)) return fail(KCR_BASE64_DECODE_ERROR, "Verify Data", "decode error");
        } else data.append(in_data);
    }

    if (flags & KC_SIGN_DRAFT) {
        Vec<const Cert*> cands;
        for (size_t i = 0; i < user_.n; ++i) cands.push(user_.d[i]);
        if (has_key_ && key_.cert) cands.push(key_.cert);
        if (!cands.n) return fail(KCR_CERTNOTFOUND, "Verify Data", "certificate not found");
        i64 now = plat_unix_time();
        bool any_time_ok = false, any_ok = false, any_chain_ok = false;
        u32 chain_rc = KCR_CACERTNOTFOUND;
        const Cert* used = 0;
        for (size_t i = 0; i < cands.n && !any_ok; ++i) {
            const Cert& c = *cands.d[i];
            bool time_ok = (flags & KC_NOCHECKCERTTIME) || (now >= c.not_before && now <= c.not_after);
            if (!time_ok) continue;
            any_time_ok = true;
            u32 crc = chain_check(c, flags);
            if (crc) { chain_rc = crc; continue; }
            if (raw_verify(c, data.span(), sig.span(), false)) { any_ok = true; used = &c; }
            any_chain_ok = true;
        }
        if (!any_time_ok) return fail(KCR_CERTTIMEINVALID, "Verify chain and certificates:", "certificate has expired or is not yet valid");
        if (!any_chain_ok) return chain_rc;
        if (!any_ok) {
            info.append_str("Verify - FAILED.\nerror:8006E07B:lib(128):GOST_EC_VERIFY:signature mismatch");
            return fail(KC_ERR_GOST_VERIFY, "Verify Data", "verify error");
        }
        info.append_str("Verify - OK");
        if (cert_id >= 1 && used) encode_cert(*used, 0, out_cert);
        note("Verify Data");
        return KCR_OK;
    }

    // CMS
    CmsMessage m;
    if (!m.parse(sig.span())) {
        info.append_str("error:0D0680A8:asn1 encoding routines:asn1_check_tlen:wrong tag");
        return fail(KCR_UNKNOWN_CMS_FORMAT, "Load CMS", "unknown CMS format");
    }
    const bool had_embedded = m.has_embedded;
    if (!det && !had_embedded) {
        info.append_str("error:2E06307F:CMS routines:check_content:no content");
        return fail(KC_ERR_CMS_NO_CONTENT, "Verify Data", "verify error");
    }
    if (det) { m.content.clear(); m.content.append(data.span()); m.has_embedded = true; }      // проверяем подпись над переданными данными
    if (!ca_.n) {
        if (inter_.n) return fail(KCR_CHECKCHAINERROR, "Verify chain and certificates:", "CA certificate not found or chain is invalid");
        fail(KCR_CACERTNOTFOUND, "Load certificate from system store", "not found root or intermediate certificate in system store");
        return KCR_CACERTNOTFOUND;
    }
    Vec<const Cert*> pool, anchors;
    for (size_t i = 0; i < inter_.n; ++i) pool.push(inter_.d[i]);
    for (size_t i = 0; i < ca_.n; ++i) anchors.push(ca_.d[i]);
    bool nocheck = (flags & KC_NOCHECKCERTTIME) != 0;
    i64 now = plat_unix_time();
    m.verify(0, anchors.d, anchors.n, pool.d, pool.n, nocheck ? 0 : now, nocheck ? CHAIN_NO_TIME : 0);
    if (!m.signers.n) return fail(KCR_NOSIGNFOUND, "Verify Data", "signature is not found");

    u32 result = KCR_OK;
    for (size_t i = 0; i < m.signers.n; ++i) {
        const SignerResult& r = m.signers[i];
        u32 sr = KCR_OK;
        if (r.state[0] == 'o' && r.state[1] == 'k') {
            if (r.cades_ok == 0) sr = KCR_CADESBES_FAILED;
        } else if (r.chain_ok == 0) sr = r.chain_rc ? r.chain_rc : KCR_CACERTNOTFOUND;
        else if (r.time_ok == 0) sr = KCR_CERTTIMEINVALID;
        else if (r.digest_ok == 0 || r.signature_ok == 0) sr = KC_ERR_CMS_VERIFY;
        else if (r.state[0] == 'n' && r.state[1] == 'o' && r.state[3] == 'c') sr = KCR_CERTNOTFOUND;     // no_certificate
        else sr = KCR_UNKNOWN_ALG;
        info.append_str("Signature N ");
        put_dec(info, i + 1);
        info.push('\n');
        if (sr == KCR_OK) {
            if (r.cades_ok == 1) info.append_str("- CAdES-BES: verify signer certificate hash - OK.\n");
            info.append_str("Verify - OK\n");
        } else {
            if (sr == KC_ERR_CMS_VERIFY) info.append_str("error:2E09A09E:CMS routines:CMS_SignerInfo_verify_content:verification failure");
            else if (sr == KCR_CADESBES_FAILED) info.append_str("- CAdES-BES: verify signer certificate hash - FAILED.\n");
            info.append_str("CMS Verify - FAILED.\n");
            if (result == KCR_OK) result = sr;
        }
    }
    if (result != KCR_OK) {
        if (result == KCR_CERTTIMEINVALID) fail(result, "Verify chain and certificates:", "certificate has expired or is not yet valid");
        else if (result == KC_ERR_CMS_VERIFY) fail(result, "Verify Data", "verify error");
        else fail(result, "Verify Data", "verify error");
        return result;
    }
    info.append_str(!det ? "CMS Verify - OK\n" : "CMS Verify - OK");     // как у KalkanCrypt: для detached без перевода строки
    if (had_embedded && !det) {
        if (flags & KC_OUT_BASE64) {
            b64_encode(m.content.span(), out_data, 64, "\n");
            if (out_data.n) out_data.push('\n');
        } else out_data.append(m.content.span());
    }
    if (cert_id >= 1) {
        size_t k = (size_t)cert_id - 1;
        if (k >= m.signers.n || m.signers[k].cert_index < 0) return fail(KCR_CERTNOTFOUND, "Verify Data", "user certificate not found");
        encode_cert(*m.certs.d[m.signers[k].cert_index], 0, out_cert);
    }
    note("Verify Data");
    return KCR_OK;
}

u32 Kalkan::GetCertFromCms(Span cms, u32 flags, int sign_id, Bytes& out) {
    out.clear();
    if (!inited_) return fail(KCR_LIBRARYNOTINITIALIZED, "Get certificate from CMS", "library not initialized");
    Bytes sig;
    u32 rc = decode_input(cms, flags & (KC_IN_FILE | KC_IN_PEM | KC_IN_BASE64 | KC_IN_DER), true, sig, "Get certificate from CMS");
    if (rc) return rc;
    CmsMessage m;
    if (!m.parse(sig.span())) return fail(KCR_UNKNOWN_CMS_FORMAT, "Load CMS", "unknown CMS format");
    m.verify(0, 0, 0, 0, 0, 0, CHAIN_NO_TIME);          // только сопоставление подписантов и сертификатов
    size_t k = sign_id <= 1 ? 0 : (size_t)sign_id - 1;
    if (k >= m.signers.n || m.signers[k].cert_index < 0) return fail(KCR_CERTNOTFOUND, "Get certificate from CMS", "user certificate not found");
    return encode_cert(*m.certs.d[m.signers[k].cert_index], flags, out);
}

u32 Kalkan::GetTimeFromSig(Span data, u32 flags, int sig_id, i64& unix_time) {
    unix_time = 0;
    if (!inited_) return fail(KCR_LIBRARYNOTINITIALIZED, "Get time from signature", "library not initialized");
    Bytes sig;
    u32 rc = decode_input(data, flags & (KC_IN_FILE | KC_IN_PEM | KC_IN_BASE64 | KC_IN_DER), true, sig, "Get time from signature");
    if (rc) return rc;
    CmsMessage m;
    if (!m.parse(sig.span())) return fail(KCR_UNKNOWN_CMS_FORMAT, "Load CMS", "unknown CMS format");
    m.verify(0, 0, 0, 0, 0, 0, CHAIN_NO_TIME);
    size_t k = sig_id <= 1 ? 0 : (size_t)sig_id - 1;
    if (k < m.signers.n && m.signers[k].has_tsa_time) { unix_time = m.signers[k].tsa_time; return KCR_OK; }
    return fail(KCR_NOTSATOKEN_, "Get time from signature", "no TSA token found in signature");
}

// ---- XML --------------------------------------------------------------------------------------------------------------

u32 Kalkan::SignXml(Span alias, u32 flags, Span node_id, Span parent, Span ns, Span in, Bytes& out, bool utf8_text) {
    (void)alias;
    out.clear();
    if (!inited_) return fail(KCR_LIBRARYNOTINITIALIZED, "XMLSec sign xml", "library not initialized");
    if (!has_key_ || !key_.cert) return fail(KCR_KEY_NOT_FOUND, "XMLSec sign xml", "private key not found");
    Bytes xml;
    if (flags & KC_IN_FILE) {
        u32 rc = decode_input(in, KC_IN_FILE, false, xml, "XMLSec sign xml");
        if (rc) return rc;
    } else xml.append(in);
    u32 rc = check_signer(key_, flags, true);
    if (rc) return rc;
    XmlSignOptions o;
    o.flags = flags;
    o.sign_node_id = node_id;
    o.parent_node = parent;
    o.parent_ns = ns;
    o.utf8_text = utf8_text && !(flags & KC_IN_FILE);
    rc = xml_sign(key_, xml.span(), o, out);
    if (rc == KCR_XMLPARSEERROR) { out.clear(); fail(rc, "XML parse doc", "FAILED"); return fail(rc, "XMLSec sign xml", "FAILED"); }
    if (rc) { out.clear(); return fail(rc, "XMLSec sign xml", "FAILED"); }
    note("XMLSec sign xml");
    return KCR_OK;
}

static void sig_alg_text(const Cert& c, Bytes& out) { cert_get_info(c, KC_CERTPROP_SIGNATURE_ALG, out); }

u32 Kalkan::VerifyXml(Span alias, u32 flags, Span in, Bytes& info, bool utf8_text) {
    (void)alias;
    info.clear();
    if (!inited_) return fail(KCR_LIBRARYNOTINITIALIZED, "XMLSec verify xml", "library not initialized");
    Bytes xml;
    if (flags & KC_IN_FILE) {
        u32 rc = decode_input(in, KC_IN_FILE, false, xml, "XMLSec verify xml");
        if (rc) return rc;
    } else xml.append(in);
    Vec<const Cert*> pool, anchors;
    for (size_t i = 0; i < inter_.n; ++i) pool.push(inter_.d[i]);
    for (size_t i = 0; i < ca_.n; ++i) anchors.push(ca_.d[i]);
    XmlVerifyOptions o;
    o.anchors = anchors.d; o.anchors_n = anchors.n;
    o.pool = pool.d; o.pool_n = pool.n;
    bool nocheck = (flags & KC_NOCHECKCERTTIME) != 0;
    o.check_time = nocheck ? 0 : plat_unix_time();
    o.chain_flags = nocheck ? CHAIN_NO_TIME : 0;
    o.utf8_text = utf8_text && !(flags & KC_IN_FILE);
    Vec<XmlSigInfo*> res;
    u32 rc = xml_verify(xml.span(), o, res);
    u32 ret = KCR_OK;
    if (rc == KCR_XMLPARSEERROR) { fail(rc, "XML parse doc", "FAILED"); ret = fail(rc, "XMLSec verify xml", "FAILED"); }
    else if (rc == KCR_NOSIGNFOUND) { ret = fail(rc, "XMLSec verify xml", "signature is not found"); }
    else if (rc) ret = fail(rc, "XMLSec verify xml", "FAILED");
    else if (!ca_.n) {
        ret = fail(KCR_LOADTRUSTEDCERTSERR, "Load certificate from system store", "not found root or intermediate certificate in system store");
    } else {
        for (size_t k = res.n; k-- > 0;) {
            XmlSigInfo* r = res.d[k];
            info.append_str("Signature N ");
            put_dec(info, (u64)r->number);
            info.push('\n');
            if (r->id.n) { info.append_str("Id = "); info.append(r->id.span()); info.push('\n'); }
            Cert c;
            if (r->cert_der.n && c.load(r->cert_der.span())) {
                Bytes t;
                cert_get_info(c, KC_CERTPROP_CERT_SN, t);
                info.append(t.span()); info.push('\n');
                t.clear(); sig_alg_text(c, t);
                info.append(t.span()); info.push('\n');
                t.clear(); cert_get_info(c, KC_CERTPROP_SUBJECT_SERIALNUMBER, t);
                if (t.n) { info.append(t.span()); info.push('\n'); }
            }
            bool ok = r->digest_ok == 1 && r->signature_ok == 1 && r->chain_ok != 0 && r->time_ok != 0;
            info.append_str(ok ? "Signature is OK\n\n" : "Signature is invalid\n\n");
            if (!ok && ret == KCR_OK) {
                if (r->chain_ok == 0) ret = inter_.n ? KCR_CACERTNOTFOUND : KCR_LOADTRUSTEDCERTSERR;
                else if (r->time_ok == 0) ret = KCR_CERTTIMEINVALID;
                else ret = KCR_SIGN_INVALID;
            }
        }
        if (ret) fail(ret, "XMLSec verify xml", "FAILED"); else note("XMLSec verify xml");
    }
    for (size_t i = 0; i < res.n; ++i) delete res.d[i];
    return ret;
}

u32 Kalkan::GetCertFromXml(Span xml, int sign_id, Bytes& out, bool utf8_text) {
    out.clear();
    if (!inited_) return fail(KCR_LIBRARYNOTINITIALIZED, "Get certificate from XML", "library not initialized");
    Bytes der;
    u32 rc = xml_get_cert(xml, sign_id, der, utf8_text);
    if (rc) return fail(rc, "Get certificate from XML", "certificate not found");
    return b64_encode(der.span(), out, 64, "\n") ? KCR_OK : KCR_MEMORY_ERROR;
}

u32 Kalkan::GetSigAlgFromXml(Span xml, Bytes& out, bool utf8_text) {
    out.clear();
    if (!inited_) return fail(KCR_LIBRARYNOTINITIALIZED, "Get signature algorithm from XML", "library not initialized");
    Bytes der;
    u32 rc = xml_get_cert(xml, 1, der, utf8_text);
    if (rc == KCR_OK) {
        Cert c;
        if (c.load(der.span())) { sig_alg_text(c, out); return KCR_OK; }
    }
    Bytes uri;
    rc = xml_get_sigalg(xml, uri, utf8_text);
    if (rc) return fail(rc, "Get signature algorithm from XML", "signature not found");
    return out.append(uri.span()) ? KCR_OK : KCR_MEMORY_ERROR;
}

// ---- настройки ---------------------------------------------------------------------------------------------------------

u32 Kalkan::TsaSetUrl(Span url) {
    tsa_url_.clear();
    tsa_url_.append(url);
    return KCR_OK;
}

u32 Kalkan::SetProxy(u32 flags, Span addr, Span port, Span user, Span pass) {
    (void)flags; (void)addr; (void)port; (void)user; (void)pass;
    return KCR_OK;
}

// ---- описание ошибок ------------------------------------------------------------------------------------------------------

const char* kc_error_text(u32 code) {
    switch (code) {
        case KCR_OK: return "Нет ошибки";
        case KCR_INIT_ERROR: return "Ошибка инициализации";
        case KCR_ERROR_READ_PKCS12: return "Невозможно прочитать файл формата PKCS#12";
        case KCR_ERROR_OPEN_PKCS12: return "Невозможно открыть файл формата PKCS#12";
        case KCR_INVALID_PROPID: return "Недопустимый идентификатор расширения сертификата";
        case KCR_BUFFER_TOO_SMALL: return "Размер буфера слишком мал";
        case KCR_CERT_PARSE_ERROR: return "Невозможно разобрать сертификат";
        case KCR_INVALID_FLAG: return "Недопустимый флаг";
        case KCR_OPENFILEERR: return "Невозможно открыть файл";
        case KCR_INVALIDPASSWORD: return "Неправильный пароль";
        case KCR_MEMORY_ERROR: return "Невозможно выделить память";
        case KCR_CHECKCHAINERROR: return "Не найден сертификат УЦ или сертификат пользователя при проверке цепочки";
        case KCR_VALIDTYPEERROR: return "Недопустимый тип валидации сертификата";
        case KCR_BADCRLFORMAT: return "Некорректный формат CRL";
        case KCR_LOADCRLERROR: return "Невозможно загрузить CRL";
        case KCR_UNKNOWN_ALG: return "Неизвестный алгоритм";
        case KCR_KEY_NOT_FOUND: return "Не найден приватный ключ пользователя";
        case KCR_SIGN_INIT_ERROR: return "Невозможно инициализировать менеджера подписи";
        case KCR_SIGN_ERROR: return "Не удалось сгенерировать цифровую подпись";
        case KCR_ENCODE_ERROR: return "Ошибка кодирования";
        case KCR_INVALID_FLAGS: return "Недопустимые флаги";
        case KCR_CERTNOTFOUND: return "Не найден сертификат пользователя";
        case KCR_VERIFYSIGNERROR: return "Ошибка верификации подписи xml";
        case KCR_BASE64_DECODE_ERROR: return "Ошибка декодирования из Base64";
        case KCR_UNKNOWN_CMS_FORMAT: return "Неизвестный формат CMS";
        case KCR_CA_CERT_NOT_FOUND: return "Не найден сертификат УЦ";
        case KCR_LOADTRUSTEDCERTSERR: return "Ошибка загрузки доверенных сертификатов";
        case KCR_SIGN_INVALID: return "Недопустимая подпись xml";
        case KCR_NOSIGNFOUND: return "Не найдена подпись во входных данных";
        case KCR_DECODE_ERROR: return "Ошибка дешифрования";
        case KCR_XMLPARSEERROR: return "Невозможно разобрать xml";
        case KCR_XMLSETSIGNERROR: return "Не удалось подписать xml";
        case KCR_NOTOKENFOUND: return "Не найден токен";
        case KCR_VERIFY_NODATA: return "Нет входных данных для верификации";
        case KCR_SIGNFORMMAT: return "Неизвестный формат подписи";
        case KCR_VERIFY_ERROR: return "Не удалось верифицировать цифровую подпись";
        case KCR_HASH_ERROR: return "Не удалось хэшировать данные";
        case KCR_SIGNHASH_ERROR: return "Не удалось подписать хэшированные данные";
        case KCR_CACERTNOTFOUND: return "Не найден сертификат УЦ в хранилище сертификатов";
        case KCR_CERTTIMEINVALID: return "Срок действия сертификата истек либо еще не наступил";
        case KCR_NOTSATOKEN_: return "В подписи не присутствует метка TSA";
        case KCR_INVALID_DIGEST_LEN: return "Неправильная длина хэша";
        case KCR_LIBRARYNOTINITIALIZED: return "Библиотека не инициализирована";
        case KCR_PARAM_ERROR: return "Некорректные входные данные";
        case KCR_CERT_STATUS_OK: return "Статус сертификата - валидный";
        case KCR_CERT_STATUS_REVOKED: return "Статус сертификата - отозван";
        case KCR_CERT_STATUS_UNKNOWN: return "Статус сертификата - неизвестен";
        case KC_ERR_GOST_VERIFY: return "Подпись не совпала (GOST_EC_VERIFY)";
        case KC_ERR_CMS_VERIFY: return "Подпись CMS не прошла проверку";
        default: return "";
    }
}

}  // namespace nek
