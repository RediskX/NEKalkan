// NEKalkan — плоский C-интерфейс (тестовый хост для автотестов).
// Это тестовый и служебный вход; рабочий вход для 1С — Native API (native1c.cpp).
#include "rt.h"
#include "hash.h"
#include "gost3410.h"
#include "ciphers.h"
#include "rsa.h"
#include "x509.h"
#include "certprop.h"
#include "keystore.h"
#include "cms.h"
#include "xml.h"
#include "xmldsig.h"
#include "api1c.h"
#include "plat.h"

using namespace nek;

extern "C" {

__declspec(dllexport) const char* nek_version() { return "NEKalkan 0.1.0"; }

// alg: 1=SHA1 2=SHA256 3=SHA384 4=SHA512 5=Streebog256 6=Streebog512
__declspec(dllexport) int nek_hash(int alg, const u8* data, size_t len, u8* out) {
    if (!hash_size((HashAlg)alg)) return -1;
    hash_data((HashAlg)alg, data, len, out);
    return (int)hash_size((HashAlg)alg);
}

__declspec(dllexport) int nek_hmac(int alg, const u8* key, size_t klen, const u8* data, size_t len, u8* out) {
    if (!hash_size((HashAlg)alg)) return -1;
    hmac((HashAlg)alg, Span(key, klen), Span(data, len), out);
    return (int)hash_size((HashAlg)alg);
}

// ---- ГОСТ Р 34.10 ----
__declspec(dllexport) int nek_gost_verify(int size, const u8* pub_le, const u8* digest, size_t dlen, const u8* sig_le) {
    const GostCurve* c = gost_curve(size);
    return c && gost3410_verify(c, Span(pub_le, 2 * size), Span(digest, dlen), Span(sig_le, 2 * size)) ? 1 : 0;
}
__declspec(dllexport) int nek_gost_sign(int size, const u8* priv_be, const u8* digest, size_t dlen, u8* sig_le) {
    const GostCurve* c = gost_curve(size);
    return c && gost3410_sign(c, Span(priv_be, size), Span(digest, dlen), sig_le) ? 1 : 0;
}
__declspec(dllexport) int nek_gost_sign_k(int size, const u8* priv_be, const u8* digest, size_t dlen, const u8* k_be, u8* sig_le) {
    const GostCurve* c = gost_curve(size);
    return c && gost3410_sign_k(c, Span(priv_be, size), Span(digest, dlen), Span(k_be, size), sig_le) ? 1 : 0;
}
__declspec(dllexport) int nek_gost_public(int size, const u8* priv_be, u8* xy_be) {
    const GostCurve* c = gost_curve(size);
    return c && gost3410_public_be(c, Span(priv_be, size), xy_be) ? 1 : 0;
}


// ---- шифры (расшифрование CBC): kind 1=DES 2=3DES 3=RC2 4=AES; effective_bits — для RC2 ----
__declspec(dllexport) int nek_cbc_decrypt(int kind, const u8* key, size_t klen, int effective_bits,
                                          const u8* iv, size_t ivlen, const u8* in, size_t n, u8* out) {
    switch (kind) {
        case 1: return des_cbc_decrypt(Span(key, klen), Span(iv, ivlen), Span(in, n), out) ? 1 : 0;
        case 2: return des3_cbc_decrypt(Span(key, klen), Span(iv, ivlen), Span(in, n), out) ? 1 : 0;
        case 3: return rc2_cbc_decrypt(Span(key, klen), effective_bits, Span(iv, ivlen), Span(in, n), out) ? 1 : 0;
        case 4: return aes_cbc_decrypt(Span(key, klen), Span(iv, ivlen), Span(in, n), out) ? 1 : 0;
    }
    return 0;
}

// ---- RSA ----
__declspec(dllexport) int nek_rsa_verify(const u8* n, size_t nl, const u8* e, size_t el, int alg,
                                         const u8* digest, size_t dl, const u8* sig, size_t sl) {
    return rsa_pkcs1_verify(Span(n, nl), Span(e, el), (HashAlg)alg, Span(digest, dl), Span(sig, sl)) ? 1 : 0;
}
__declspec(dllexport) int nek_rsa_sign(const u8* n, size_t nl, const u8* e, size_t el, const u8* p, size_t pl,
                                       const u8* q, size_t ql, const u8* dp, size_t dpl, const u8* dq, size_t dql,
                                       const u8* qi, size_t qil, int alg, const u8* digest, size_t dl, u8* sig_out) {
    RsaPrivKey k;
    if (!k.n.append(n, nl) || !k.e.append(e, el) || !k.p.append(p, pl) || !k.q.append(q, ql) ||
        !k.dp.append(dp, dpl) || !k.dq.append(dq, dql) || !k.qinv.append(qi, qil)) return 0;
    Bytes sig;
    if (!rsa_pkcs1_sign(k, (HashAlg)alg, Span(digest, dl), sig)) return 0;
    memcpy(sig_out, sig.p, sig.n);
    return (int)sig.n;
}


// ---- сертификаты ----
// Свойство KC_CERTPROP_*: возвращает длину (≥0), или -(код ошибки KCR)
__declspec(dllexport) int nek_cert_info(const u8* der, size_t n, u32 prop, u8* out, size_t cap) {
    Cert c;
    if (!c.load(Span(der, n))) return -(int)KCR_CERT_PARSE_ERROR;
    Bytes b;
    u32 rc = cert_get_info(c, prop, b);
    if (rc) return -(int)(rc & 0xFFFF) - 1;
    if (b.n > cap) return -2;
    memcpy(out, b.p, b.n);
    return (int)b.n;
}
__declspec(dllexport) int nek_cert_verify(const u8* der, size_t n, const u8* issuer, size_t m) {
    Cert c, i;
    if (!c.load(Span(der, n)) || !i.load(Span(issuer, m))) return -1;
    return cert_verify_signature(c, i) ? 1 : 0;
}
// цепочка: leaf, pool (массив DER подряд с префиксом длины u32), anchor
__declspec(dllexport) u32 nek_chain_validate(const u8* leaf, size_t ln, const u8* pool_blob, size_t pool_len,
                                             const u8* anchor, size_t an, i64 when, u32 flags) {
    Cert c, a;
    if (!c.load(Span(leaf, ln)) || !a.load(Span(anchor, an))) return KCR_CERT_PARSE_ERROR;
    Vec<Cert*> pool;
    size_t pos = 0;
    while (pos + 4 <= pool_len) {
        u32 l = pool_blob[pos] | (pool_blob[pos + 1] << 8) | (pool_blob[pos + 2] << 16) | ((u32)pool_blob[pos + 3] << 24);
        pos += 4;
        if (pos + l > pool_len) break;
        Cert* pc = new Cert();
        if (!pc->load(Span(pool_blob + pos, l))) return KCR_CERT_PARSE_ERROR;
        pool.push(pc);
        pos += l;
    }
    const Cert* an_arr[1] = {&a};
    u32 rc = chain_validate(c, (const Cert* const*)pool.d, pool.n, an_arr, 1, when, flags);
    for (size_t i = 0; i < pool.n; ++i) delete pool.d[i];
    return rc;
}


// ---- PKCS#12, CMS, RAW (тестовые обёртки) ----
__declspec(dllexport) int nek_p12_info(const u8* p12, size_t n, const char* pw, u8* cert_out, size_t cap, u8* key_out, size_t keycap, int* keytype) {
    SignKey k;
    u32 rc = p12_load(Span(p12, n), Span(pw, cstrlen(pw)), k);
    if (rc) return -(int)(rc & 0xFFFF) - 1;
    *keytype = k.type;
    if (k.cert->der.n > cap) return -2;
    memcpy(cert_out, k.cert->der.p, k.cert->der.n);
    if (key_out && k.type == KEY_GOST2015 && k.gost_priv.n <= keycap) memcpy(key_out, k.gost_priv.p, k.gost_priv.n);
    return (int)k.cert->der.n;
}
__declspec(dllexport) int nek_cms_sign_p12(const u8* p12, size_t n, const char* pw, const u8* data, size_t dn,
                                           int detached, int with_cert, u8* out, size_t cap) {
    SignKey k;
    u32 rc = p12_load(Span(p12, n), Span(pw, cstrlen(pw)), k);
    if (rc) return -(int)(rc & 0xFFFF) - 1;
    CmsSignOptions o;
    o.detached = detached != 0;
    o.with_cert = with_cert != 0;
    Bytes b;
    if (!cms_sign(k, Span(data, dn), o, b)) return -2;
    if (b.n > cap) return -3;
    memcpy(out, b.p, b.n);
    return (int)b.n;
}
__declspec(dllexport) int nek_raw_sign_p12(const u8* p12, size_t n, const char* pw, const u8* data, size_t dn, u8* out, size_t cap) {
    SignKey k;
    u32 rc = p12_load(Span(p12, n), Span(pw, cstrlen(pw)), k);
    if (rc) return -(int)(rc & 0xFFFF) - 1;
    Bytes b;
    if (!raw_sign(k, Span(data, dn), b)) return -2;
    if (b.n > cap) return -3;
    memcpy(out, b.p, b.n);
    return (int)b.n;
}
__declspec(dllexport) int nek_raw_verify_cert(const u8* cert, size_t cn, const u8* data, size_t dn, const u8* sig, size_t sn, int prehashed) {
    Cert c;
    if (!c.load(Span(cert, cn))) return -1;
    return raw_verify(c, Span(data, dn), Span(sig, sn), prehashed != 0) ? 1 : 0;
}
// Сводка по подписантам CMS: по строке на подписанта «state;digest;sig;chain;time;digest_oid;sig_oid;has_time;time;tsa»
__declspec(dllexport) int nek_cms_verify_summary(const u8* cms, size_t n, const u8* det, size_t dn, int has_det,
                                                 const u8* anchor, size_t an, i64 when, char* out, size_t cap) {
    CmsMessage m;
    if (!m.parse(Span(cms, n))) return -1000 - m.fail_line;
    Bytes d;
    if (has_det) d.append(det, dn);
    Cert a;
    const Cert* ap[1] = {&a};
    bool use_anchor = anchor && an && a.load(Span(anchor, an));
    m.verify(has_det ? &d : 0, use_anchor ? ap : 0, use_anchor ? 1 : 0, 0, 0, when, 0);
    Bytes s;
    for (size_t i = 0; i < m.signers.n; ++i) {
        const SignerResult& r = m.signers[i];
        char line[512];
        // ручное форматирование без snprintf
        s.append_str(r.state); s.push(';');
        const int vals[4] = {r.digest_ok, r.signature_ok, r.chain_ok, r.time_ok};
        for (int k = 0; k < 4; ++k) { s.push((u8)(vals[k] < 0 ? '-' : '0' + vals[k])); s.push(';'); }
        s.append_str(r.digest_oid); s.push(';'); s.append_str(r.sig_oid); s.push(';');
        s.push(r.has_time ? '1' : '0'); s.push(';');
        { u64 t = (u64)r.signing_time; char tmp[24]; int kk = 0; if (!t) tmp[kk++] = '0'; while (t) { tmp[kk++] = (char)('0' + t % 10); t /= 10; } while (kk) s.push((u8)tmp[--kk]); }
        s.push(';'); s.push(r.has_tsa ? '1' : '0'); s.push(0x0A);
        (void)line;
    }
    s.append_str("content_len=");
    { u64 t = m.content.n; char tmp[24]; int kk = 0; if (!t) tmp[kk++] = '0'; while (t) { tmp[kk++] = (char)('0' + t % 10); t /= 10; } while (kk) s.push((u8)tmp[--kk]); }
    s.push(0x0A);
    if (s.n + 1 > cap) return -2;
    memcpy(out, s.p, s.n + 1);
    return (int)s.n;
}


// ---- XML: каноникализация и сериализация (тест) ----
static bool skip_ds_sig(const XNode* n, void*) {
    return n->kind == XK_ELEM && n->local.eq(Span("Signature")) && n->ns.eq(Span(DS_NS));
}
// flags: 1 = exclusive, 2 = с комментариями, 4 = C14N 1.1, 8 = пропустить все ds:Signature; id — Id элемента (пусто — весь документ);
// incl — список InclusiveNamespaces через пробел (может быть пусто)
__declspec(dllexport) int nek_xml_c14n(const u8* xml, size_t n, int flags, const char* id, const char* incl, u8* out, size_t cap) {
    XDoc d;
    if (!d.parse(Span(xml, n))) return -1;
    C14nOptions o;
    o.exclusive = flags & 1; o.comments = (flags & 2) != 0; o.v11 = (flags & 4) != 0;
    Vec<Span> pl;
    if (incl && incl[0]) {
        const char* p = incl;
        while (*p) {
            while (*p == ' ') ++p;
            const char* b = p;
            while (*p && *p != ' ') ++p;
            if (p > b) {
                if (p - b == 8 && mem_eq(b, "#default", 8)) pl.push(Span((const u8*)"", 0)); else pl.push(Span((const u8*)b, (size_t)(p - b)));
            }
        }
        o.incl_prefixes = pl.d; o.incl_n = pl.n;
    }
    const XNode* apex = d.doc;
    if (id && id[0]) { apex = d.find_by_id(Span(id)); if (!apex) return -2; }
    Bytes b;
    if (!xml_c14n(apex, (flags & 8) ? skip_ds_sig : 0, 0, o, b)) return -3;
    if (b.n > cap) return -4;
    memcpy(out, b.p, b.n);
    return (int)b.n;
}
__declspec(dllexport) int nek_xml_serialize(const u8* xml, size_t n, u8* out, size_t cap) {
    XDoc d;
    if (!d.parse(Span(xml, n))) return -1;
    Bytes b;
    if (!xml_serialize(d, b)) return -3;
    if (b.n > cap) return -4;
    memcpy(out, b.p, b.n);
    return (int)b.n;
}


// ---- XMLDSig (тест) ----
__declspec(dllexport) int nek_xml_sign_p12(const u8* p12, size_t n, const char* pw, const u8* xml, size_t xn, u32 flags,
                                           const char* node_id, const char* parent, const char* parent_ns, u8* out, size_t cap) {
    SignKey k;
    u32 rc = p12_load(Span(p12, n), Span(pw, cstrlen(pw)), k);
    if (rc) return -(int)(rc & 0xFFFF) - 1000;
    XmlSignOptions o;
    o.flags = flags;
    o.sign_node_id = Span(node_id, cstrlen(node_id));
    o.parent_node = Span(parent, cstrlen(parent));
    o.parent_ns = Span(parent_ns, cstrlen(parent_ns));
    Bytes b;
    rc = xml_sign(k, Span(xml, xn), o, b);
    if (rc) return -(int)(rc & 0xFFFF);
    if (b.n > cap) return -1;
    memcpy(out, b.p, b.n);
    return (int)b.n;
}

// Сводка: по строке на подпись «номер;id;digest;sig;chain;time;метод». Возвращает длину или -код.
__declspec(dllexport) int nek_xml_verify_summary(const u8* xml, size_t n, const u8* anchor, size_t an, i64 when, char* out, size_t cap) {
    Cert a;
    const Cert* ap[1] = {&a};
    bool use = anchor && an && a.load(Span(anchor, an));
    XmlVerifyOptions o;
    o.anchors = use ? ap : 0;
    o.anchors_n = use ? 1 : 0;
    o.check_time = when;
    Vec<XmlSigInfo*> res;
    u32 rc = xml_verify(Span(xml, n), o, res);
    if (rc) return -(int)(rc & 0xFFFF);
    Bytes s;
    auto num = [&](int v) { s.push((u8)(v < 0 ? '-' : '0' + v)); };
    for (size_t i = 0; i < res.n; ++i) {
        XmlSigInfo* r = res.d[i];
        char t[12]; int k = 0; int v = r->number; if (!v) t[k++] = '0'; while (v) { t[k++] = (char)('0' + v % 10); v /= 10; }
        while (k) s.push((u8)t[--k]);
        s.push(';'); s.append(r->id.span()); s.push(';');
        num(r->digest_ok); s.push(';'); num(r->signature_ok); s.push(';'); num(r->chain_ok); s.push(';'); num(r->time_ok); s.push(';');
        s.append(r->sig_method.span()); s.push(';');
        s.push(r->cert_der.n ? '1' : '0');
        s.push(0x0A);
        delete r;
    }
    if (s.n + 1 > cap) return -2;
    memcpy(out, s.p, s.n + 1);
    return (int)s.n;
}


// ---- вызов методов компоненты (тестовый хост ApiHost) ----
struct NekArg { int kind; i64 i; const u8* p; size_t n; };    // kind: 0 пусто, 1 число, 2 текст (UTF-8), 3 BLOB

struct NekSlot { int kind; i64 i; Bytes b; };

struct TestHost : ApiHost {
    const NekArg* args;
    int n;
    NekSlot slots[18];                 // 0..n-1 — BYREF-параметры, 17 — возвращаемое значение
    int enc = ENC_UTF8;
    TestHost(const NekArg* a, int cnt) : args(a), n(cnt) { for (auto& s : slots) { s.kind = 0; s.i = 0; } }
    NekSlot& slot(int i) { return slots[i < 0 ? 17 : (i > 16 ? 16 : i)]; }
    int arg_count() override { return n; }
    bool arg_int(int i, i64& v) override {
        if (i < 0 || i >= n) return false;
        if (args[i].kind != 1) return false;
        v = args[i].i;
        return true;
    }
    bool arg_name(int i, Bytes& out) override { return arg_data(i, out); }
    bool arg_data(int i, Bytes& out) override {
        if (i < 0 || i >= n) return false;
        if (args[i].kind == 0) return true;
        if (args[i].kind == 1) return false;
        return out.append(args[i].p, args[i].n);
    }
    bool arg_xml(int i, Bytes& out, bool& was_text) override {
        was_text = i >= 0 && i < n && args[i].kind == 2;
        return arg_data(i, out);
    }
    bool put_int(int i, i64 v) override { NekSlot& s = slot(i); s.kind = 1; s.i = v; return true; }
    bool put_text(int i, Span b) override { NekSlot& s = slot(i); s.kind = 2; s.b.clear(); return s.b.append(b); }
    bool put_data(int i, Span b) override {
        NekSlot& s = slot(i); s.b.clear();
        s.kind = utf8_valid(b) ? 2 : 3;
        return s.b.append(b);
    }
    bool put_blob(int i, Span b) override { NekSlot& s = slot(i); s.kind = 3; s.b.clear(); return s.b.append(b); }
    bool set_encoding(Span name) override { return api_parse_encoding(name, enc); }
    const char* encoding_name() override { return api_encoding_name(enc); }
};

__declspec(dllexport) void* nek_api_new() { return new ApiState(); }
__declspec(dllexport) void nek_api_free(void* h) { delete (ApiState*)h; }
// Возвращает объект результата (освободить nek_call_free) либо 0, если метод не найден.
__declspec(dllexport) void* nek_call(void* h, int method, const NekArg* args, int nargs) {
    TestHost* th = new TestHost(args, nargs);
    if (!api_call(*(ApiState*)h, method, *th)) { delete th; return 0; }
    return th;
}
__declspec(dllexport) void nek_call_free(void* r) { delete (TestHost*)r; }
// slot: 0..nargs-1 — BYREF-параметры, -1 — возвращаемое значение
__declspec(dllexport) int nek_call_kind(void* r, int slot) { return ((TestHost*)r)->slot(slot).kind; }
__declspec(dllexport) i64 nek_call_int(void* r, int slot) { return ((TestHost*)r)->slot(slot).i; }
__declspec(dllexport) const u8* nek_call_data(void* r, int slot, size_t* len) {
    NekSlot& s = ((TestHost*)r)->slot(slot);
    *len = s.b.n;
    return s.b.p;
}
__declspec(dllexport) int nek_api_method_count() { return API_METHOD_COUNT; }
__declspec(dllexport) const char* nek_api_method_name(int i) { return i >= 0 && i < API_METHOD_COUNT ? API_METHODS[i].en : 0; }

}

extern "C" __declspec(dllexport) long nek_live_allocs() { return nek::plat_live_allocs(); }
