// NEKalkan — свойства сертификата (KC_CERTPROP_*).
#include "certprop.h"
#include "plat.h"

namespace nek {

struct Prefix { const char* oid; const char* name; };
static const Prefix NAME_PREFIX[] = {
    {"2.5.4.6", "C"}, {"2.5.4.8", "ST"}, {"2.5.4.7", "L"}, {"2.5.4.10", "O"}, {"2.5.4.11", "OU"},
    {"2.5.4.3", "CN"}, {"2.5.4.42", "GN"}, {"2.5.4.4", "SN"}, {"2.5.4.5", "serialNumber"},
    {"1.2.840.113549.1.9.1", "E"}, {"2.5.4.15", "businessCategory"}, {"0.9.2342.19200300.100.1.25", "DC"},
};

static const char* prefix_for(const char* oid) {
    for (const Prefix& p : NAME_PREFIX) {
        size_t i = 0;
        while (p.oid[i] && oid[i] == p.oid[i]) ++i;
        if (!p.oid[i] && !oid[i]) return p.name;
    }
    return 0;
}

bool name_to_dn(Span name, Bytes& out) {
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
            char oid[128];
            if (!oid_to_str(o.val, oid, sizeof(oid))) return false;
            const char* pf = prefix_for(oid);
            if (!out.push('/') || !out.append_str(pf ? pf : oid) || !out.push('=')) return false;
            if (!asn_string_to_utf8(v.tag, v.val, out)) return false;
        }
    }
    return true;
}

static bool named(Span name, const char* oid, Bytes& out) {
    Bytes v;
    if (!name_get(name, oid, v) || v.n == 0) return true;      // пусто — это не ошибка
    return out.append_str(prefix_for(oid)) && out.push('=') && out.append(v.span());
}

static void put_num(Bytes& out, int v, int width) {
    char tmp[12];
    int k = 0;
    for (int i = 0; i < width; ++i) { tmp[k++] = (char)('0' + v % 10); v /= 10; }
    while (k) out.push((u8)tmp[--k]);
}

static bool fmt_local(i64 t, Bytes& out) {
    DateTime d;
    from_unix(t + plat_local_offset(t), d);
    put_num(out, d.day, 2); out.push('.'); put_num(out, d.month, 2); out.push('.'); put_num(out, d.year, 4);
    out.push(' ');
    put_num(out, d.hour, 2); out.push(':'); put_num(out, d.min, 2); out.push(':'); put_num(out, d.sec, 2);
    return true;
}

struct EkuName { const char* oid; const char* name; };
static const EkuName EKU_NAMES[] = {
    {"1.3.6.1.5.5.7.3.1", "TLS Web Server Authentication"}, {"1.3.6.1.5.5.7.3.2", "TLS Web Client Authentication"},
    {"1.3.6.1.5.5.7.3.3", "Code Signing"}, {"1.3.6.1.5.5.7.3.4", "E-mail Protection"},
    {"1.3.6.1.5.5.7.3.8", "Time Stamping"}, {"1.3.6.1.5.5.7.3.9", "OCSP Signing"},
};

struct SigName { const char* oid; const char* name; };
static const SigName SIG_NAMES[] = {
    {"1.2.398.3.10.1.1.2.3.2", "GOST R 34.10-2015 with GOST R 34.11-2015 (512 bit)"},
    {"1.2.398.3.10.1.1.1.1", "GOST R 34.10-2001 with GOST R 34.11-94"},
    {"1.2.643.7.1.1.3.2", "GOST R 34.10-2012 with GOST R 34.11-2012 (256 bit)"},
    {"1.2.643.7.1.1.3.3", "GOST R 34.10-2012 with GOST R 34.11-2012 (512 bit)"},
};

static const char* const KU_NAMES[9] = {"digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment",
                                        "keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly"};

static bool oid_str(Span c, char* buf, size_t cap) { return oid_to_str(c, buf, cap); }

// Полный путь сертификата → ISSUER/SUBJECT свойства
struct NameProp { u32 id; const char* oid; };
static const NameProp ISSUER_PROPS[] = {
    {KC_CERTPROP_ISSUER_COUNTRYNAME, "2.5.4.6"}, {KC_CERTPROP_ISSUER_SOPN, "2.5.4.8"}, {KC_CERTPROP_ISSUER_LOCALITYNAME, "2.5.4.7"},
    {KC_CERTPROP_ISSUER_ORG_NAME, "2.5.4.10"}, {KC_CERTPROP_ISSUER_ORGUNIT_NAME, "2.5.4.11"}, {KC_CERTPROP_ISSUER_COMMONNAME, "2.5.4.3"},
};
static const NameProp SUBJECT_PROPS[] = {
    {KC_CERTPROP_SUBJECT_COUNTRYNAME, "2.5.4.6"}, {KC_CERTPROP_SUBJECT_SOPN, "2.5.4.8"}, {KC_CERTPROP_SUBJECT_LOCALITYNAME, "2.5.4.7"},
    {KC_CERTPROP_SUBJECT_COMMONNAME, "2.5.4.3"}, {KC_CERTPROP_SUBJECT_GIVENNAME, "2.5.4.42"}, {KC_CERTPROP_SUBJECT_SURNAME, "2.5.4.4"},
    {KC_CERTPROP_SUBJECT_SERIALNUMBER, "2.5.4.5"}, {KC_CERTPROP_SUBJECT_EMAIL, "1.2.840.113549.1.9.1"},
    {KC_CERTPROP_SUBJECT_ORG_NAME, "2.5.4.10"}, {KC_CERTPROP_SUBJECT_ORGUNIT_NAME, "2.5.4.11"},
    {KC_CERTPROP_SUBJECT_BC, "2.5.4.15"}, {KC_CERTPROP_SUBJECT_DC, "0.9.2342.19200300.100.1.25"},
};

// Собирает URL из AccessDescription/DistributionPoint: ищем IA5String с тегом 0x86 (uniformResourceIdentifier).
static void collect_uris(Span der, Vec<Span>& uris, int depth = 0) {
    if (depth > 8) return;
    while (der.n) {
        Tlv t;
        if (!der_next(der, t)) return;
        if (t.tag == 0x86) { uris.push(t.val); continue; }
        if (t.tag & 0x20) collect_uris(t.val, uris, depth + 1);
    }
}

u32 cert_get_info(const Cert& c, u32 prop, Bytes& out) {
    out.clear();
    for (const NameProp& p : ISSUER_PROPS)
        if (p.id == prop) return named(c.issuer, p.oid, out) ? KCR_OK : KCR_MEMORY_ERROR;
    for (const NameProp& p : SUBJECT_PROPS)
        if (p.id == prop) return named(c.subject, p.oid, out) ? KCR_OK : KCR_MEMORY_ERROR;

    switch (prop) {
        case KC_CERTPROP_NOTBEFORE:
            out.append_str("notBefore="); fmt_local(c.not_before, out); out.push(' ');
            return KCR_OK;
        case KC_CERTPROP_NOTAFTER:
            out.append_str("notAfter="); fmt_local(c.not_after, out); out.push(' ');
            return KCR_OK;
        case KC_CERTPROP_CERT_SN: {
            out.append_str("certificateSerialNumber=");
            Span m = int_magnitude(c.serial);
            Bytes hex;
            hex_encode(m, hex, true);
            size_t i = 0;
            while (i + 1 < hex.n && hex.p[i] == '0') ++i;
            out.append(hex.p + i, hex.n - i);
            return KCR_OK;
        }
        case KC_CERTPROP_ISSUER_DN:
            return name_to_dn(c.issuer, out) ? KCR_OK : KCR_CERT_PARSE_ERROR;
        case KC_CERTPROP_SUBJECT_DN:
            return name_to_dn(c.subject, out) ? KCR_OK : KCR_CERT_PARSE_ERROR;
        case KC_CERTPROP_SIGNATURE_ALG: {
            char oid[128];
            if (!oid_str(c.sig_alg_oid, oid, sizeof(oid))) return KCR_CERT_PARSE_ERROR;
            const char* nm = "";
            for (const SigName& s : SIG_NAMES) {
                size_t i = 0;
                while (s.oid[i] && oid[i] == s.oid[i]) ++i;
                if (!s.oid[i] && !oid[i]) nm = s.name;
            }
            out.append_str("signatureAlgorithm="); out.append_str(nm); out.push('('); out.append_str(oid); out.push(')');
            return KCR_OK;
        }
        case KC_CERTPROP_PUBKEY:
            return b64_encode(c.spki, out, 64, "\n") ? KCR_OK : KCR_MEMORY_ERROR;
        case KC_CERTPROP_KEY_USAGE: {
            if (!c.has_ku) return KCR_OK;
            bool any = false;
            Bytes tmp;
            for (int i = 0; i < 9; ++i)
                if (c.ku & (1u << i)) { if (any) tmp.push(' '); tmp.append_str(KU_NAMES[i]); any = true; }
            if (!any) return KCR_OK;
            out.append_str("keyUsage="); out.append(tmp.span()); out.push(' ');
            return KCR_OK;
        }
        case KC_CERTPROP_EXT_KEY_USAGE: {
            Span v;
            if (!c.find_ext("2.5.29.37", v)) return KCR_OK;
            Tlv seq;
            Span vs = v;
            if (!der_expect(vs, T_SEQUENCE, seq)) return KCR_OK;
            Span in = seq.val;
            Bytes tmp;
            while (in.n) {
                Tlv o;
                if (!der_next(in, o) || o.tag != T_OID) break;
                char oid[128];
                if (!oid_str(o.val, oid, sizeof(oid))) break;
                const char* nm = oid;
                for (const EkuName& e : EKU_NAMES) {
                    size_t i = 0;
                    while (e.oid[i] && oid[i] == e.oid[i]) ++i;
                    if (!e.oid[i] && !oid[i]) nm = e.name;
                }
                tmp.append_str(nm); tmp.append_str(" ("); tmp.append_str(oid); tmp.append_str("); ");
            }
            if (tmp.n) { out.append_str("extendedKeyUsage="); out.append(tmp.span()); }
            return KCR_OK;
        }
        case KC_CERTPROP_AUTH_KEY_ID: {
            Span v;
            if (!c.find_ext("2.5.29.35", v)) return KCR_OK;
            Tlv seq;
            Span vs = v;
            if (!der_expect(vs, T_SEQUENCE, seq)) return KCR_OK;
            Span in = seq.val;
            while (in.n) {
                Tlv t;
                if (!der_next(in, t)) break;
                if (t.tag == 0x80) { out.append_str("authorityKeyIdentifier="); hex_encode(t.val, out, true); break; }
            }
            return KCR_OK;
        }
        case KC_CERTPROP_SUBJ_KEY_ID: {
            Span v;
            if (!c.find_ext("2.5.29.14", v)) return KCR_OK;
            Tlv t;
            Span vs = v;
            if (!der_expect(vs, T_OCTETSTRING, t)) return KCR_OK;
            out.append_str("subjectKeyIdentifier="); hex_encode(t.val, out, true);
            return KCR_OK;
        }
        case KC_CERTPROP_POLICIES_ID: {
            Span v;
            if (!c.find_ext("2.5.29.32", v)) return KCR_OK;
            Tlv seq;
            Span vs = v;
            if (!der_expect(vs, T_SEQUENCE, seq)) return KCR_OK;
            Span in = seq.val;
            Bytes tmp;
            while (in.n) {
                Tlv pi, o;
                if (!der_next(in, pi) || pi.tag != T_SEQUENCE) break;
                Span pin = pi.val;
                if (!der_expect(pin, T_OID, o)) break;
                char oid[128];
                if (!oid_str(o.val, oid, sizeof(oid))) break;
                if (tmp.n) tmp.append_str(", ");
                tmp.append_str(oid);
            }
            if (tmp.n) { out.append_str("certificatePolicies="); out.append(tmp.span()); }
            return KCR_OK;
        }
        case KC_CERTPROP_OCSP: {
            Span v;
            if (!c.find_ext("1.3.6.1.5.5.7.1.1", v)) return KCR_OK;
            Tlv seq;
            Span vs = v;
            if (!der_expect(vs, T_SEQUENCE, seq)) return KCR_OK;
            Span in = seq.val;
            Bytes tmp;
            while (in.n) {
                Tlv ad, o;
                if (!der_next(in, ad) || ad.tag != T_SEQUENCE) break;
                Span ain = ad.val;
                if (!der_expect(ain, T_OID, o)) break;
                if (!oid_is(o.val, "1.3.6.1.5.5.7.48.1")) continue;
                Tlv loc;
                if (!der_next(ain, loc) || loc.tag != 0x86) continue;
                if (tmp.n) tmp.append_str(", ");
                tmp.append(loc.val);
            }
            if (tmp.n) { out.append_str("OCSP="); out.append(tmp.span()); }
            return KCR_OK;
        }
        case KC_CERTPROP_GET_CRL:
        case KC_CERTPROP_GET_DELTA_CRL: {
            Span v;
            if (!c.find_ext(prop == KC_CERTPROP_GET_CRL ? "2.5.29.31" : "2.5.29.46", v)) return KCR_OK;
            Vec<Span> uris;
            collect_uris(v, uris);
            if (!uris.n) return KCR_OK;
            out.append_str(prop == KC_CERTPROP_GET_CRL ? "crlDistributionPoints=" : "freshestCRL=");
            for (size_t i = 0; i < uris.n; ++i) { out.append(uris[i]); out.append_str("; "); }
            return KCR_OK;
        }
        default:
            return KCR_INVALID_PROPID;
    }
}

}  // namespace nek
