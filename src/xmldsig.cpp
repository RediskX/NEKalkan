// NEKalkan — XMLDSig.
#include "xmldsig.h"
#include "gost3410.h"
#include "rsa.h"
#include "hash.h"
#include "plat.h"

namespace nek {

static const char* const URI_C14N = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
static const char* const URI_C14N_C = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";
static const char* const URI_C14N11 = "http://www.w3.org/2006/12/xml-c14n11";
static const char* const URI_C14N11_C = "http://www.w3.org/2006/12/xml-c14n11#WithComments";
static const char* const URI_EXC = "http://www.w3.org/2001/10/xml-exc-c14n#";
static const char* const URI_EXC_C = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";
static const char* const URI_ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
static const char* const URI_SIG_G256 = "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34102015-gostr34112015-256";
static const char* const URI_SIG_G512 = "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34102015-gostr34112015-512";
static const char* const URI_DIG_G256 = "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34112015-256";
static const char* const URI_DIG_G512 = "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34112015-512";
static const char* const URI_SIG_RSA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
static const char* const URI_DIG_SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";

static bool eq(Span s, const char* c) { return s.n == cstrlen(c) && mem_eq(s.p, c, s.n); }

// ---- разбор алгоритмов -------------------------------------------------------------------

static bool c14n_by_uri(Span uri, C14nOptions& o) {
    o = C14nOptions();
    if (eq(uri, URI_C14N)) return true;
    if (eq(uri, URI_C14N_C)) { o.comments = true; return true; }
    if (eq(uri, URI_C14N11)) { o.v11 = true; return true; }
    if (eq(uri, URI_C14N11_C)) { o.v11 = true; o.comments = true; return true; }
    if (eq(uri, URI_EXC)) { o.exclusive = true; return true; }
    if (eq(uri, URI_EXC_C)) { o.exclusive = true; o.comments = true; return true; }
    return false;
}

static bool hash_by_digest_uri(Span uri, HashAlg& h) {
    if (eq(uri, URI_DIG_G256)) { h = H_STREEBOG256; return true; }
    if (eq(uri, URI_DIG_G512)) { h = H_STREEBOG512; return true; }
    if (eq(uri, "http://www.w3.org/2001/04/xmldsig-more#gost34311")) { h = H_GOST94; return true; }
    if (eq(uri, "http://www.w3.org/2000/09/xmldsig#sha1")) { h = H_SHA1; return true; }
    if (eq(uri, "http://www.w3.org/2001/04/xmlenc#sha256")) { h = H_SHA256; return true; }
    if (eq(uri, "http://www.w3.org/2001/04/xmldsig-more#sha384")) { h = H_SHA384; return true; }
    if (eq(uri, "http://www.w3.org/2001/04/xmlenc#sha512")) { h = H_SHA512; return true; }
    return false;
}

// ---- вспомогательное для DOM -------------------------------------------------------------------

static bool is_ds(const XNode* n, const char* local) {
    return n->kind == XK_ELEM && eq(n->local, local) && eq(n->ns, DS_NS);
}

static const XNode* ds_child(const XNode* p, const char* local) {
    for (const XNode* c = p->first; c; c = c->next)
        if (is_ds(c, local)) return c;
    return 0;
}

static void elem_text(const XNode* n, Bytes& out) {
    for (const XNode* c = n->first; c; c = c->next) {
        if (c->kind == XK_TEXT || c->kind == XK_CDATA) out.append(c->text);
        else if (c->kind == XK_ELEM) elem_text(c, out);
    }
}

// false — не хватило памяти (иначе часть подписей молча выпала бы из проверки)
static bool collect_sigs(const XNode* n, Vec<const XNode*>& out) {
    for (const XNode* c = n->first; c; c = c->next) {
        if (c->kind != XK_ELEM) continue;
        if (is_ds(c, "Signature") && !out.push(c)) return false;
        if (!collect_sigs(c, out)) return false;
    }
    return true;
}

// parent лежит внутри поддерева node (или совпадает с ним)
static bool is_within(const XNode* parent, const XNode* node) {
    for (const XNode* n = parent; n; n = n->parent) if (n == node) return true;
    return false;
}

// Какие подписи исключать из набора узлов при enveloped-преобразовании:
//   mode 0 — свою и все последующие (так KalkanCrypt накладывает подписи друг на друга: каждая следующая
//            подпись покрывает документ вместе с предыдущими), 1 — только свою (стандарт), 2 — все.
struct SkipCtx {
    const XNode* own;
    int mode;
    const Vec<const XNode*>* sigs;
    size_t own_index;
};
static bool skip_sigs(const XNode* n, void* p) {
    SkipCtx* c = (SkipCtx*)p;
    if (!is_ds(n, "Signature")) return false;
    if (c->mode == 2) return true;
    if (n == c->own) return true;
    if (c->mode == 0 && c->sigs) {
        for (size_t i = c->own_index + 1; i < c->sigs->n; ++i)
            if (c->sigs->d[i] == n) return true;
    }
    return false;
}

// InclusiveNamespaces PrefixList из дочернего элемента
static void read_prefix_list(const XNode* method, Vec<Span>& pl) {
    for (const XNode* c = method->first; c; c = c->next) {
        if (c->kind != XK_ELEM || !eq(c->local, "InclusiveNamespaces")) continue;
        const XAttr* a = c->attr_local("PrefixList");
        if (!a) continue;
        const u8* p = a->value.p;
        size_t n = a->value.n, i = 0;
        while (i < n) {
            while (i < n && p[i] == ' ') ++i;
            size_t b = i;
            while (i < n && p[i] != ' ') ++i;
            if (i > b) {
                if (i - b == 8 && mem_eq(p + b, "#default", 8)) pl.push(Span((const u8*)"", 0));
                else pl.push(Span(p + b, i - b));
            }
        }
    }
}

static bool b64_text(const XNode* n, Bytes& out) {
    Bytes t;
    elem_text(n, t);
    return b64_decode(t.span(), out);
}

static const char* const SIG_OID_RSA_SHA1 = "1.2.840.113549.1.1.5";
static const char* const SIG_OID_RSA_SHA256 = "1.2.840.113549.1.1.11";
static const char* const SIG_OID_RSA_SHA384 = "1.2.840.113549.1.1.12";
static const char* const SIG_OID_RSA_SHA512 = "1.2.840.113549.1.1.13";

// ---- подпись ----------------------------------------------------------------------------------------

static void c14n_ref_options(u32 flags, C14nOptions& o, const char*& uri) {
    o = C14nOptions();
    if (flags & 0x01u) { uri = URI_C14N; }
    else if (flags & 0x02u) { o.comments = true; uri = URI_C14N_C; }
    else if (flags & 0x04u) { o.v11 = true; uri = URI_C14N11; }
    else if (flags & 0x08u) { o.v11 = true; o.comments = true; uri = URI_C14N11_C; }
    else if (flags & 0x10u) { o.exclusive = true; uri = URI_EXC; }
    else if (flags & 0x20u) { o.exclusive = true; o.comments = true; uri = URI_EXC_C; }
    else { o.comments = true; uri = URI_C14N_C; }          // по умолчанию — как у KalkanCrypt: C14N WithComments
}

static void c14n_si_options(u32 flags, C14nOptions& o, const char*& uri) {
    o = C14nOptions();
    if (flags & 0x40u) { uri = URI_C14N; }
    else if (flags & 0x80u) { o.comments = true; uri = URI_C14N_C; }
    else if (flags & 0x100u) { o.v11 = true; uri = URI_C14N11; }
    else if (flags & 0x200u) { o.v11 = true; o.comments = true; uri = URI_C14N11_C; }
    else if (flags & 0x400u) { o.exclusive = true; uri = URI_EXC; }
    else if (flags & 0x800u) { o.exclusive = true; o.comments = true; uri = URI_EXC_C; }
    else { uri = URI_C14N; }
}

static bool put_dec(Bytes& b, int v) {
    char tmp[12];
    int k = 0;
    if (v == 0) tmp[k++] = '0';
    while (v) { tmp[k++] = (char)('0' + v % 10); v /= 10; }
    while (k) if (!b.push((u8)tmp[--k])) return false;
    return true;
}

// Текст ds:Signature. sigvalue пусто — заготовка для канонизации SignedInfo.
static bool build_signature(Bytes& raw, int number, const char* ref_uri_attr, bool enveloped, const char* c14n_si_uri,
                            const char* c14n_ref_uri, const char* sig_uri, const char* dig_uri, Span digest_b64,
                            Span sigvalue_b64, Span cert_b64) {
    bool ok = raw.append_str("<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" Id=\"") && put_dec(raw, number) &&
              raw.append_str("\">\n<ds:SignedInfo>\n<ds:CanonicalizationMethod Algorithm=\"") &&
              raw.append_str(c14n_si_uri) && raw.append_str("\"/>\n<ds:SignatureMethod Algorithm=\"") &&
              raw.append_str(sig_uri) && raw.append_str("\"/>\n<ds:Reference URI=\"") && raw.append_str(ref_uri_attr) &&
              raw.append_str("\">\n<ds:Transforms>\n");
    if (ok && enveloped)
        ok = raw.append_str("<ds:Transform Algorithm=\"") && raw.append_str(URI_ENVELOPED) && raw.append_str("\"/>\n");
    ok = ok && raw.append_str("<ds:Transform Algorithm=\"") && raw.append_str(c14n_ref_uri) &&
         raw.append_str("\"/>\n</ds:Transforms>\n<ds:DigestMethod Algorithm=\"") && raw.append_str(dig_uri) &&
         raw.append_str("\"/>\n<ds:DigestValue>") && raw.append(digest_b64) &&
         raw.append_str("</ds:DigestValue>\n</ds:Reference>\n</ds:SignedInfo>\n<ds:SignatureValue>") && raw.append(sigvalue_b64) &&
         raw.append_str("</ds:SignatureValue>\n<ds:KeyInfo>\n<ds:X509Data>\n<ds:X509Certificate>") && raw.append(cert_b64) &&
         raw.append_str("</ds:X509Certificate>\n</ds:X509Data>\n</ds:KeyInfo>\n</ds:Signature>");
    return ok;
}

u32 xml_sign(const SignKey& key, Span xml, const XmlSignOptions& opt, Bytes& out) {
    if (!key.cert || key.type == KEY_NONE) return KCR_KEY_NOT_FOUND;
    XDoc d;
    if (!d.parse(xml, opt.utf8_text)) return KCR_XMLPARSEERROR;

    bool gost = key.type == KEY_GOST2015;
    HashAlg halg = gost ? (key.gost_size == 64 ? H_STREEBOG512 : H_STREEBOG256) : H_SHA256;
    const char* sig_uri = gost ? (key.gost_size == 64 ? URI_SIG_G512 : URI_SIG_G256) : URI_SIG_RSA256;
    const char* dig_uri = gost ? (key.gost_size == 64 ? URI_DIG_G512 : URI_DIG_G256) : URI_DIG_SHA256;

    // что подписываем
    bool whole = opt.sign_node_id.n == 0;
    const XNode* ref_node = d.doc;
    Bytes uri_attr;
    if (!whole) {
        ref_node = d.find_by_id(opt.sign_node_id);
        if (!ref_node) return d.id_exists(opt.sign_node_id) ? KCR_XMLADDIDERROR : KCR_XMLSETSIGNERROR;   // как у Калкана: дубликат Id — 0x08F00027
        uri_attr.push('#');
        xml_escape_attr(opt.sign_node_id, uri_attr);
    }
    // куда кладём подпись
    const XNode* parent = d.root;
    if (opt.parent_node.n) {
        const XNode* p = d.find_element(d.doc, opt.parent_node, opt.parent_ns);
        if (p) parent = p;
    }
    // Подпись вставляется внутрь подписываемого узла — нужен enveloped-transform (иначе при проверке она вошла бы в дайджест)
    const bool enveloped = whole || is_within(parent, ref_node);
    C14nOptions ref_opt, si_opt;
    const char* ref_c14n_uri;
    const char* si_c14n_uri;
    c14n_ref_options(opt.flags, ref_opt, ref_c14n_uri);
    c14n_si_options(opt.flags, si_opt, si_c14n_uri);

    Vec<const XNode*> existing;
    if (!collect_sigs(d.doc, existing)) return KCR_MEMORY_ERROR;
    // Уже готовая «заготовка» с пустым SignatureValue во входном документе недопустима: иначе компонента могла бы подписать чужой SignedInfo.
    for (size_t i = 0; i < existing.n; ++i) {
        const XNode* sv = ds_child(existing.d[i], "SignatureValue");
        if (!sv || !sv->first) return KCR_XMLSETSIGNERROR;
    }
    // Id подписи: порядковый номер, но не занятый другим элементом документа (иначе ссылка «#номер» стала бы неоднозначной)
    int number = (int)existing.n + 1;
    for (;;) {
        Bytes num;
        put_dec(num, number);
        if (!d.id_exists(num.span())) break;
        ++number;
    }

    // дайджест ссылки
    Bytes canon;
    // Комментарии при разыменовании same-document ссылки (URI="" или "#id") в набор узлов не попадают
    // (XMLDSig §4.3.3.3), даже если преобразование — C14N WithComments. Предыдущие подписи документа входят в дайджест.
    C14nOptions ref_eff = ref_opt;
    ref_eff.comments = false;
    if (!xml_c14n(ref_node, 0, 0, ref_eff, canon)) return KCR_XMLINTERNALERROR;
    u8 dg[64];
    hash_data(halg, canon.span(), dg);
    Bytes dig_b64, cert_b64;
    if (!b64_encode(Span(dg, hash_size(halg)), dig_b64, 64, "\n") || !b64_encode(key.cert->der.span(), cert_b64, 64, "\n")) return KCR_MEMORY_ERROR;

    // 1) заготовка без SignatureValue
    Bytes raw1, text1;
    if (!build_signature(raw1, number, uri_attr.cstr(), enveloped, si_c14n_uri, ref_c14n_uri, sig_uri, dig_uri, dig_b64.span(), Span(),
                         cert_b64.span())) return KCR_MEMORY_ERROR;
    if (!xml_serialize(d, text1, parent, raw1.span())) return KCR_MEMORY_ERROR;

    // 2) разбор получившегося документа, каноникализация SignedInfo в контексте документа
    XDoc d2;
    if (!d2.parse(text1.span())) return KCR_XMLINTERNALERROR;
    Vec<const XNode*> all2;
    if (!collect_sigs(d2.doc, all2)) return KCR_MEMORY_ERROR;
    const XNode* mine = 0;
    int empties = 0;
    for (size_t i = 0; i < all2.n; ++i) {
        const XNode* sv = ds_child(all2.d[i], "SignatureValue");
        if (sv && !sv->first) { mine = all2.d[i]; ++empties; }
    }
    if (!mine || empties != 1) return KCR_XMLINTERNALERROR;
    const XNode* si = ds_child(mine, "SignedInfo");
    if (!si) return KCR_XMLINTERNALERROR;
    Bytes si_canon;
    SkipCtx none = {0, 1, 0, 0};
    if (!xml_c14n(si, 0, &none, si_opt, si_canon)) return KCR_XMLINTERNALERROR;

    // 3) подпись
    u8 sd[64];
    hash_data(halg, si_canon.span(), sd);
    Bytes sig;
    if (gost) {
        const GostCurve* c = gost_curve(key.gost_size);
        if (!c || !sig.resize(2 * (size_t)key.gost_size)) return KCR_SIGN_ERROR;
        if (!gost3410_sign(c, key.gost_priv.span(), Span(sd, hash_size(halg)), sig.p)) return KCR_SIGN_ERROR;
    } else {
        if (!rsa_pkcs1_sign(key.rsa, H_SHA256, Span(sd, hash_size(halg)), sig)) return KCR_SIGN_ERROR;
    }
    Bytes sig_b64;
    if (!b64_encode(sig.span(), sig_b64, 64, "\n")) return KCR_MEMORY_ERROR;

    // 4) итог: тот же документ, подпись с SignatureValue
    Bytes raw2;
    if (!build_signature(raw2, number, uri_attr.cstr(), enveloped, si_c14n_uri, ref_c14n_uri, sig_uri, dig_uri, dig_b64.span(),
                         sig_b64.span(), cert_b64.span())) return KCR_MEMORY_ERROR;
    out.clear();
    if (!xml_serialize(d, out, parent, raw2.span())) return KCR_MEMORY_ERROR;
    return KCR_OK;
}

// ---- проверка --------------------------------------------------------------------------------------------

static bool verify_signature_value(const Cert& cert, Span sig_method, Span signed_info_c14n, Span sig) {
    bool unsup = false;
    Bytes oid;
    if (eq(sig_method, URI_SIG_G256) || eq(sig_method, URI_SIG_G512)) {
        if (!oid_encode(OID_KZ_GOST2015_SIG, oid)) return false;
        return verify_with_cert_key(cert, oid.span(), Span(), signed_info_c14n, sig, &unsup);
    }
    if (eq(sig_method, "http://www.w3.org/2001/04/xmldsig-more#gost34310-gost34311")) {
        if (!oid_encode(OID_KZ_LEGACY_SIG, oid)) return false;
        return verify_with_cert_key(cert, oid.span(), Span(), signed_info_c14n, sig, &unsup);
    }
    const char* rsa_oid = 0;
    if (eq(sig_method, "http://www.w3.org/2000/09/xmldsig#rsa-sha1")) rsa_oid = SIG_OID_RSA_SHA1;
    else if (eq(sig_method, URI_SIG_RSA256)) rsa_oid = SIG_OID_RSA_SHA256;
    else if (eq(sig_method, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384")) rsa_oid = SIG_OID_RSA_SHA384;
    else if (eq(sig_method, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512")) rsa_oid = SIG_OID_RSA_SHA512;
    if (!rsa_oid || !oid_encode(rsa_oid, oid)) return false;
    return verify_with_cert_key(cert, oid.span(), Span(), signed_info_c14n, sig, &unsup);
}

static bool check_reference(const XDoc& d, const XNode* sig_node, const Vec<const XNode*>& sigs, size_t sig_index, const XNode* ref) {
    const XAttr* ua = ref->attr_local("URI");
    Span uri = ua ? ua->value : Span((const u8*)"", 0);
    const XNode* apex = 0;
    if (uri.n == 0) apex = d.doc;
    else if (uri.p[0] == '#') apex = d.find_by_id(Span(uri.p + 1, uri.n - 1));
    if (!apex) return false;
    const XNode* dm = ds_child(ref, "DigestMethod");
    const XNode* dv = ds_child(ref, "DigestValue");
    if (!dm || !dv) return false;
    const XAttr* da = dm->attr_local("Algorithm");
    HashAlg h;
    if (!da || !hash_by_digest_uri(da->value, h)) return false;
    Bytes expect;
    if (!b64_text(dv, expect)) return false;

    bool enveloped = false;
    C14nOptions copt;                       // умолчание: C14N 1.0 без комментариев
    Vec<Span> pl;
    const XNode* trs = ds_child(ref, "Transforms");
    if (trs) {
        for (const XNode* t = trs->first; t; t = t->next) {
            if (!is_ds(t, "Transform")) continue;
            const XAttr* a = t->attr_local("Algorithm");
            if (!a) return false;
            if (eq(a->value, URI_ENVELOPED)) { enveloped = true; continue; }
            C14nOptions o;
            if (!c14n_by_uri(a->value, o)) return false;       // иные преобразования не поддержаны
            copt = o;
            read_prefix_list(t, pl);
        }
    }
    copt.incl_prefixes = pl.d;
    copt.incl_n = pl.n;
    copt.comments = false;                  // см. xml_sign: у same-document ссылок комментарии исключены
    for (int attempt = 0; attempt < 2; ++attempt) {
        if (attempt > 0 && !enveloped) break;
        SkipCtx sc = {sig_node, attempt == 0 ? 0 : (attempt == 1 ? 1 : 2), &sigs, sig_index};
        Bytes canon;
        if (!xml_c14n(apex, enveloped ? skip_sigs : 0, &sc, copt, canon)) return false;
        u8 dg[64];
        hash_data(h, canon.span(), dg);
        if (expect.n == hash_size(h) && ct_eq(dg, expect.p, expect.n)) return true;
    }
    return false;
}

u32 xml_verify(Span xml, const XmlVerifyOptions& opt, Vec<XmlSigInfo*>& results) {
    XDoc d;
    if (!d.parse(xml, opt.utf8_text)) return KCR_XMLPARSEERROR;
    Vec<const XNode*> sigs;
    if (!collect_sigs(d.doc, sigs)) return KCR_MEMORY_ERROR;
    if (!sigs.n) return KCR_NOSIGNFOUND;
    for (size_t si = 0; si < sigs.n; ++si) {
        const XNode* s = sigs.d[si];
        XmlSigInfo* r = new XmlSigInfo();
        if (!r) return KCR_MEMORY_ERROR;
        if (!results.push(r)) { delete r; return KCR_MEMORY_ERROR; }
        r->number = (int)si + 1;
        const XAttr* ida = s->attr_local("Id");
        if (ida) r->id.append(ida->value);
        const XNode* sinfo = ds_child(s, "SignedInfo");
        const XNode* sval = ds_child(s, "SignatureValue");
        if (!sinfo || !sval) continue;
        const XNode* cm = ds_child(sinfo, "CanonicalizationMethod");
        const XNode* sm = ds_child(sinfo, "SignatureMethod");
        if (!cm || !sm) continue;
        const XAttr* cma = cm->attr_local("Algorithm");
        const XAttr* sma = sm->attr_local("Algorithm");
        if (!cma || !sma) continue;
        r->sig_method.append(sma->value);

        // ссылки
        bool all_refs = false;
        int nrefs = 0;
        all_refs = true;
        for (const XNode* c = sinfo->first; c; c = c->next) {
            if (!is_ds(c, "Reference")) continue;
            ++nrefs;
            if (!check_reference(d, s, sigs, si, c)) all_refs = false;
        }
        r->digest_ok = (nrefs > 0 && all_refs) ? 1 : 0;

        // сертификат
        Bytes cert_der;
        const XNode* ki = ds_child(s, "KeyInfo");
        if (ki) {
            const XNode* xd = ds_child(ki, "X509Data");
            if (xd) {
                const XNode* xc = ds_child(xd, "X509Certificate");
                if (xc) b64_text(xc, cert_der);
            }
        }
        r->cert_der.append(cert_der.span());
        Cert own;
        const Cert* signer = opt.signer;
        if (!signer) {
            if (!cert_der.n || !own.load(cert_der.span())) { r->signature_ok = 0; continue; }
            signer = &own;
        }

        // подпись SignedInfo
        C14nOptions co;
        if (!c14n_by_uri(cma->value, co)) { r->signature_ok = 0; continue; }
        Vec<Span> pl;
        read_prefix_list(cm, pl);
        co.incl_prefixes = pl.d;
        co.incl_n = pl.n;
        Bytes canon, sig;
        SkipCtx none = {0, 1, 0, 0};
        if (!xml_c14n(sinfo, 0, &none, co, canon) || !b64_text(sval, sig)) { r->signature_ok = 0; continue; }
        r->signature_ok = verify_signature_value(*signer, sma->value, canon.span(), sig.span()) ? 1 : 0;

        if (opt.anchors_n) {
            u32 rc = chain_validate(*signer, opt.pool, opt.pool_n, opt.anchors, opt.anchors_n, opt.check_time, opt.chain_flags);
            r->chain_ok = rc == KCR_OK ? 1 : 0;
        }
        if (opt.check_time) r->time_ok = (opt.check_time >= signer->not_before && opt.check_time <= signer->not_after) ? 1 : 0;
    }
    return KCR_OK;
}

u32 xml_get_cert(Span xml, int index, Bytes& cert_der, bool utf8_text) {
    XDoc d;
    if (!d.parse(xml, utf8_text)) return KCR_XMLPARSEERROR;
    Vec<const XNode*> sigs;
    if (!collect_sigs(d.doc, sigs)) return KCR_MEMORY_ERROR;
    if (!sigs.n) return KCR_NOSIGNFOUND;
    size_t k = index <= 1 ? 0 : (size_t)index - 1;
    if (k >= sigs.n) return KCR_IDRANGE;
    const XNode* ki = ds_child(sigs.d[k], "KeyInfo");
    const XNode* xd = ki ? ds_child(ki, "X509Data") : 0;
    const XNode* xc = xd ? ds_child(xd, "X509Certificate") : 0;
    if (!xc) return KCR_CERTNOTFOUND;
    cert_der.clear();
    return b64_text(xc, cert_der) ? KCR_OK : KCR_BASE64_DECODE_ERROR;
}

u32 xml_get_sigalg(Span xml, Bytes& uri, bool utf8_text) {
    XDoc d;
    if (!d.parse(xml, utf8_text)) return KCR_XMLPARSEERROR;
    Vec<const XNode*> sigs;
    if (!collect_sigs(d.doc, sigs)) return KCR_MEMORY_ERROR;
    if (!sigs.n) return KCR_NOSIGNFOUND;
    const XNode* si = ds_child(sigs.d[0], "SignedInfo");
    const XNode* sm = si ? ds_child(si, "SignatureMethod") : 0;
    const XAttr* a = sm ? sm->attr_local("Algorithm") : 0;
    if (!a) return KCR_XMLINTERNALERROR;
    uri.clear();
    return uri.append(a->value) ? KCR_OK : KCR_MEMORY_ERROR;
}

}  // namespace nek
