// NEKalkan — диспетчер методов компоненты 1С (api_call).
#include "api1c.h"
#include "codec.h"
#include "plat.h"

namespace nek {

// Данные из api1c.cpp


static const u32 WRAP_INVALID_PARAMETER_ = 0x0A510005;
static const u32 WRAP_CONVERSION_ERROR_ = 0x0A510007;
static const u32 WRAP_NOT_IMPLEMENTED_ = 0x0A51000C;

namespace {

bool put_value(ApiHost& h, int idx, Span data, bool want_blob) {
    if (want_blob || !utf8_valid(data)) return h.put_blob(idx, data);
    return h.put_text(idx, data);
}

// BYREF-результат + код возврата, либо значение (Result-вариант)
void emit(ApiHost& h, int out_idx, bool as_value, u32 rc, Span data, bool blob, bool status_ok = false) {
    bool ok = rc == KCR_OK || (status_ok && (rc == KCR_CERT_STATUS_OK || rc == KCR_CERT_STATUS_REVOKED || rc == KCR_CERT_STATUS_UNKNOWN));
    if (as_value) {
        if (ok) put_value(h, -1, data, blob);
        else h.put_text(-1, Span(""));
        return;
    }
    if (ok && out_idx >= 0 && out_idx < h.arg_count()) put_value(h, out_idx, data, blob);
    h.put_int(-1, (i64)rc);
}

struct Ctx {
    ApiState& st;
    ApiHost& h;
    size_t mark;
    Ctx(ApiState& s, ApiHost& host) : st(s), h(host), mark(0) {
        if (s.kc.log().n > 16384) s.kc.ClearLog();      // журнал движка не должен расти без предела в долгоживущем сеансе
        mark = s.kc.log().n;
    }

    u32 done(u32 rc, bool status_ok = false) {
        if (rc == KCR_OK || (status_ok && rc == KCR_CERT_STATUS_OK)) st.clear_error();
        else st.set_error_from_engine(rc, mark);
        return rc;
    }
    bool num(int i, u32& v, const char* what) {
        i64 x;
        if (i >= h.arg_count() || !h.arg_int(i, x)) {
            Bytes msg;
            msg.append_str(what);
            msg.append_str(" должен быть числом.");
            st.set_error(WRAP_INVALID_PARAMETER_, msg.cstr());
            return false;
        }
        v = (u32)x;
        return true;
    }
    bool num64(int i, i64& v) { return i < h.arg_count() && h.arg_int(i, v); }
    bool conv_fail = false;       // параметр-строка/данные не удалось получить (не тот тип, не представим в кодировке)
    Span data(int i, Bytes& store) { store.clear(); if (i < h.arg_count() && !h.arg_data(i, store)) conv_fail = true; return store.span(); }
    Span name(int i, Bytes& store) { store.clear(); if (i < h.arg_count() && !h.arg_name(i, store)) conv_fail = true; return store.span(); }
    bool xml(int i, Bytes& store, bool& was_text) {
        store.clear(); was_text = true;
        if (i < h.arg_count() && !h.arg_xml(i, store, was_text)) conv_fail = true;
        return !conv_fail;
    }
    // Вызвать после чтения параметров: при сбое преобразования операция не выполняется.
    bool args_ok(bool as_value) {
        if (!conv_fail) return true;
        st.set_error(WRAP_CONVERSION_ERROR_, "Ошибка преобразования параметров: ожидалась строка или двоичные данные в поддерживаемой кодировке.");
        if (as_value) h.put_text(-1, Span(""));
        else h.put_int(-1, WRAP_CONVERSION_ERROR_);
        return false;
    }
    void bad(bool as_value) {
        if (as_value) h.put_text(-1, Span(""));
        else h.put_int(-1, WRAP_INVALID_PARAMETER_);
    }
};

// Результат подписи — текст, если это Base64/PEM, иначе двоичные данные.
bool sign_out_is_blob(u32 flags) {
    bool cms = (flags & KC_SIGN_CMS) && !(flags & KC_SIGN_DRAFT);
    if (flags & KC_OUT_DER) return true;
    if (flags & KC_OUT_BASE64) return false;
    if (cms && (flags & KC_OUT_PEM)) return false;
    return true;
}

void m_sign_data(Ctx& c, bool as_value, bool force_blob, bool with_insign) {
    u32 flags;
    if (!c.num(1, flags, "SignData: flags")) { c.bad(as_value); return; }
    Bytes alias, data, insign, out;
    c.name(0, alias);
    c.data(2, data);
    if (with_insign) c.data(3, insign);
    if (!c.args_ok(as_value)) return;
    u32 rc = c.st.kc.SignData(alias.span(), flags, data.span(), insign.span(), out);
    c.done(rc);
    emit(c.h, 3, as_value, rc, out.span(), force_blob || sign_out_is_blob(flags));
}

void m_sign_hash(Ctx& c, bool as_value) {
    u32 flags;
    if (!c.num(1, flags, "SignHash: flags")) { c.bad(as_value); return; }
    Bytes alias, hash, out;
    c.name(0, alias);
    c.data(2, hash);
    if (!c.args_ok(as_value)) return;
    u32 rc = c.st.kc.SignHash(alias.span(), flags, hash.span(), out);
    c.done(rc);
    emit(c.h, 3, as_value, rc, out.span(), sign_out_is_blob(flags));
}

void m_hash_data(Ctx& c, bool as_value) {
    u32 flags;
    if (!c.num(1, flags, "HashData: flags")) { c.bad(as_value); return; }
    Bytes alg, data, out;
    c.name(0, alg);
    c.data(2, data);
    if (!c.args_ok(as_value)) return;
    u32 rc = c.st.kc.HashData(alg.span(), flags, data.span(), out);
    c.done(rc);
    emit(c.h, 3, as_value, rc, out.span(), !(flags & KC_OUT_BASE64));
}

void m_sign_xml(Ctx& c, bool as_value) {
    u32 flags;
    if (!c.num(1, flags, "SignXML: flags")) { c.bad(as_value); return; }
    // порядок COM: alias, flags, signNodeId, parentSignNode, parentNameSpace, inData, outSign
    Bytes alias, node, parent, ns, xml, out;
    bool was_text = true;
    c.name(0, alias); c.name(2, node); c.name(3, parent); c.name(4, ns);
    c.xml(5, xml, was_text);
    if (!c.args_ok(as_value)) return;
    u32 rc = c.st.kc.SignXml(alias.span(), flags, node.span(), parent.span(), ns.span(), xml.span(), out, was_text);
    c.done(rc);
    emit(c.h, 6, as_value, rc, out.span(), false);
}

void m_verify_data(Ctx& c, bool as_value) {
    u32 flags;
    if (!c.num(1, flags, "VerifyData: flags")) { c.bad(as_value); return; }
    u32 cert_id = 0;
    if (!as_value && !c.num(6, cert_id, "VerifyData: inCertID")) { c.bad(false); return; }
    Bytes alias, data, sig, out_data, info, out_cert;
    c.name(0, alias);
    c.data(2, data);
    c.data(3, sig);
    if (!c.args_ok(as_value)) return;
    u32 rc = c.st.kc.VerifyData(alias.span(), flags, data.span(), sig.span(), (int)cert_id, out_data, info, out_cert);
    c.done(rc);
    if (as_value) {
        if (rc == KCR_OK) put_value(c.h, -1, info.span(), false); else c.h.put_text(-1, Span(""));
        return;
    }
    // BYREF: outData(4), outVerifyInfo(5), outCert(7) — результат записывается и при ошибке проверки: info объясняет причину
    if (4 < c.h.arg_count()) {
        if (flags & KC_OUT_DER) c.h.put_blob(4, out_data.span()); else c.h.put_data(4, out_data.span());
    }
    if (5 < c.h.arg_count()) put_value(c.h, 5, info.span(), false);
    if (7 < c.h.arg_count()) put_value(c.h, 7, out_cert.span(), (flags & KC_OUT_DER) != 0);
    c.h.put_int(-1, (i64)rc);
}

void put_text_list(ApiHost& h, const Bytes& t) { h.put_text(-1, t.span()); }

}  // namespace

bool api_call(ApiState& st, int m, ApiHost& h) {
    if (m < 0 || m >= API_METHOD_COUNT) return false;
    Ctx c(st, h);
    Kalkan& kc = st.kc;
    switch (m) {
        case M_Init: {
            u32 rc = kc.Init();
            c.done(rc);
            h.put_int(-1, rc);
            return true;
        }
        case M_Finalize: {
            kc.Finalize();
            st.clear_error();
            h.put_int(-1, 0);
            return true;
        }
        case M_SetKalkanPath: case M_SetKalkanDirectory: case M_SetKeyStoreTempDirectory: {
            // NEKalkan не использует внешнюю DLL Калкана и временные файлы ключей: настройки принимаются и игнорируются
            st.clear_error();
            h.put_int(-1, 0);
            return true;
        }
        case M_GetKalkanPath: case M_GetDefaultKalkanPath: case M_GetKeyStoreTempDirectory:
            h.put_text(-1, Span(m == M_GetKeyStoreTempDirectory ? "" : "(встроенный движок NEKalkan)"));
            return true;
        case M_LoadKeyStore: case M_LoadKeyStoreSafe: {
            u32 storage;
            if (!c.num(0, storage, "LoadKeyStore: storage")) { c.bad(false); return true; }
            Bytes pw, container, alias;
            c.name(1, pw); c.name(2, container); c.name(3, alias);
            if (!c.args_ok(false)) return true;
            u32 rc = kc.LoadKeyStore(storage, pw.span(), container.span(), alias.span());
            c.done(rc);
            h.put_int(-1, rc);
            return true;
        }
        case M_X509ExportCertificateFromStore: case M_ExportCertificate: {
            u32 flag;
            if (!c.num(1, flag, "X509ExportCertificateFromStore: flag")) { c.bad(m == M_ExportCertificate); return true; }
            Bytes alias, out;
            c.name(0, alias);
            if (!c.args_ok(m == M_ExportCertificate)) return true;
            u32 rc = kc.ExportCert(alias.span(), flag, out);
            c.done(rc);
            bool blob = (flag & KC_OUT_DER) != 0 || (flag & 0x101) == 0x101;
            emit(h, 2, m == M_ExportCertificate, rc, out.span(), blob);
            return true;
        }
        case M_SignData: m_sign_data(c, false, false, false); return true;
        case M_SignDataText: m_sign_data(c, true, false, true); return true;
        case M_SignDataBlob: m_sign_data(c, true, true, true); return true;
        case M_SignDataResult: m_sign_data(c, true, false, true); return true;
        case M_SignDataResult3: m_sign_data(c, true, false, false); return true;
        case M_X509CertificateGetInfo: case M_CertificateGetInfo: {
            u32 prop;
            if (!c.num(1, prop, "X509CertificateGetInfo: propId")) { c.bad(m == M_CertificateGetInfo); return true; }
            Bytes cert, out;
            c.data(0, cert);
            if (!c.args_ok(m == M_CertificateGetInfo)) return true;
            u32 rc = kc.CertGetInfo(cert.span(), prop, out);
            c.done(rc);
            emit(h, 2, m == M_CertificateGetInfo, rc, out.span(), false);
            return true;
        }
        case M_GetLastErrorString:
            h.put_text(0, st.err_text.span());
            h.put_int(1, (i64)st.err_code);
            h.put_int(-1, 0);
            return true;
        case M_GetLastErrorText: h.put_text(-1, st.err_text.span()); return true;
        case M_GetLastErrorCode: case M_GetLastError: h.put_int(-1, (i64)st.err_code); return true;
        case M_SetStringEncoding: {
            Bytes enc;
            c.name(0, enc);
            if (!c.args_ok(false)) return true;
            if (!h.set_encoding(enc.span())) {
                st.set_error(WRAP_INVALID_PARAMETER_, "Поддерживаются кодировки ACP, UTF-8, UTF8, CP1251, 1251.");
                h.put_int(-1, WRAP_INVALID_PARAMETER_);
            } else {
                st.clear_error();
                h.put_int(-1, 0);
            }
            return true;
        }
        case M_GetStringEncoding: h.put_text(-1, Span(h.encoding_name())); return true;
        case M_GetWrapperVersion: h.put_text(-1, Span("NEKalkan " NEK_VERSION " (native, без KalkanCrypt.dll)")); return true;
        case M_GetMethodList: {
            Bytes t;
            for (int i = 0; i < API_METHOD_COUNT; ++i) {
                char num[12]; int k = 0, v = i;
                if (!v) num[k++] = '0';
                while (v) { num[k++] = (char)('0' + v % 10); v /= 10; }
                while (k) t.push((u8)num[--k]);
                t.append_str(": "); t.append_str(API_METHODS[i].en); t.append_str(" / "); t.append_str(API_METHODS[i].ru); t.append_str("\r\n");
            }
            put_text_list(h, t);
            return true;
        }
        case M_GetPropertyList: {
            Bytes t;
            for (int i = 0; i < API_CONST_COUNT; ++i) {
                const char* cname; i32 cvalue;
                api_const(i, &cname, &cvalue);
                char num[16]; int k = 0; i64 v = (u32)cvalue;
                t.append_str(cname); t.append_str(" = ");
                if (!v) num[k++] = '0';
                while (v) { num[k++] = (char)('0' + v % 10); v /= 10; }
                while (k) t.push((u8)num[--k]);
                t.append_str(" (0x");
                u32 u = (u32)cvalue; char hx[9]; int hn = 0;
                if (!u) hx[hn++] = '0';
                while (u) { hx[hn++] = "0123456789ABCDEF"[u & 15]; u >>= 4; }
                while (hn) t.push((u8)hx[--hn]);
                t.append_str(")\r\n");
            }
            put_text_list(h, t);
            return true;
        }
        case M_GetErrorName: {
            i64 code = 0;
            if (!c.num64(0, code)) { h.put_text(-1, Span("WRAP_INVALID_PARAMETER")); return true; }
            h.put_text(-1, Span(api_error_name((u32)code)));
            return true;
        }
        case M_GetLastErrorFull: {
            Bytes t;
            t.append_str("Код ");
            char num[16]; int k = 0; u64 v = st.err_code;
            if (!v) num[k++] = '0';
            while (v) { num[k++] = (char)('0' + v % 10); v /= 10; }
            while (k) t.push((u8)num[--k]);
            t.append_str(" (0x");
            u32 u = st.err_code; char hx[9]; int hn = 0;
            if (!u) hx[hn++] = '0';
            while (u) { hx[hn++] = "0123456789ABCDEF"[u & 15]; u >>= 4; }
            while (hn) t.push((u8)hx[--hn]);
            t.append_str(") ");
            t.append_str(api_error_name(st.err_code));
            if (st.err_text.n) { t.append_str(": "); t.append(st.err_text.span()); }
            put_text_list(h, t);
            return true;
        }
        case M_GetTokens: {
            u32 storage = 0;
            c.num(0, storage, "GetTokens: storage");
            Bytes out; u32 count;
            u32 rc = kc.GetTokens(storage, out, count);
            c.done(rc);
            if (rc == KCR_OK) h.put_text(-1, out.span()); else h.put_text(-1, Span(""));
            return true;
        }
        case M_GetCertificatesList: {
            Bytes out; u32 count;
            u32 rc = kc.GetCertificatesList(out, count);
            c.done(rc);
            if (rc == KCR_OK) h.put_text(-1, out.span()); else h.put_text(-1, Span(""));
            return true;
        }
        case M_X509LoadCertificateFromFile: {
            u32 type;
            if (!c.num(1, type, "X509LoadCertificateFromFile: certType")) { c.bad(false); return true; }
            Bytes path;
            c.name(0, path);
            if (!c.args_ok(false)) return true;
            u32 rc = kc.LoadCertFromFile(path.span(), type);
            c.done(rc);
            h.put_int(-1, rc);
            return true;
        }
        case M_X509LoadCertificateFromBuffer: {
            u32 flag;
            if (!c.num(1, flag, "X509LoadCertificateFromBuffer: flag")) { c.bad(false); return true; }
            Bytes cert;
            c.data(0, cert);
            if (!c.args_ok(false)) return true;
            u32 rc = kc.LoadCertFromBuffer(cert.span(), flag);
            c.done(rc);
            h.put_int(-1, rc);
            return true;
        }
        case M_X509ValidateCertificate: case M_X509ValidateCertificateResult: {
            bool as_value = m == M_X509ValidateCertificateResult;
            u32 vtype, flags;
            i64 ct = 0;
            if (!c.num(1, vtype, "X509ValidateCertificate: validType")) { c.bad(as_value); return true; }
            if (as_value) { if (!c.num(3, flags, "X509ValidateCertificate: flags")) { c.bad(true); return true; } }
            else if (!c.num64(3, ct) || !c.num(4, flags, "X509ValidateCertificate: flags")) {
                c.st.set_error(WRAP_INVALID_PARAMETER_, "X509ValidateCertificate: validType/checkTime/flags имеют неверный тип.");
                c.bad(false);
                return true;
            }
            Bytes cert, vpath, info, ocsp;
            c.data(0, cert);
            c.name(2, vpath);
            if (!c.args_ok(as_value)) return true;
            u32 rc = kc.ValidateCert(cert.span(), vtype, vpath.span(), ct, flags, info, ocsp);
            c.done(rc, true);
            if (as_value) { emit(h, -1, true, rc, info.span(), false, true); return true; }
            if (rc == KCR_OK || rc == KCR_CERT_STATUS_OK || rc == KCR_CERT_STATUS_REVOKED || rc == KCR_CERT_STATUS_UNKNOWN) {
                if (5 < h.arg_count()) put_value(h, 5, info.span(), false);
                if (6 < h.arg_count()) put_value(h, 6, ocsp.span(), false);
            }
            h.put_int(-1, (i64)rc);
            return true;
        }
        case M_HashData: m_hash_data(c, false); return true;
        case M_HashDataResult: m_hash_data(c, true); return true;
        case M_SignHash: m_sign_hash(c, false); return true;
        case M_SignHashResult: m_sign_hash(c, true); return true;
        case M_SignXML: case M_SignXMLNative: m_sign_xml(c, false); return true;
        case M_SignXMLResult: case M_SignXMLNativeResult: m_sign_xml(c, true); return true;
        case M_VerifyData: m_verify_data(c, false); return true;
        case M_VerifyDataResult: m_verify_data(c, true); return true;
        case M_VerifyXML: case M_VerifyXMLResult: {
            bool as_value = m == M_VerifyXMLResult;
            u32 flags;
            if (!c.num(1, flags, "VerifyXML: flags")) { c.bad(as_value); return true; }
            Bytes alias, xml, info;
            bool was_text = true;
            c.name(0, alias);
            c.xml(2, xml, was_text);
            if (!c.args_ok(as_value)) return true;
            u32 rc = kc.VerifyXml(alias.span(), flags, xml.span(), info, was_text);
            c.done(rc);
            if (as_value) { emit(h, -1, true, rc, info.span(), false); return true; }
            if (3 < h.arg_count()) put_value(h, 3, info.span(), false);
            h.put_int(-1, (i64)rc);
            return true;
        }
        case M_GetCertFromXML: {
            u32 id = 0;
            c.num(1, id, "GetCertFromXML: signID");
            Bytes xml, out;
            bool was_text = true;
            c.xml(0, xml, was_text);
            if (!c.args_ok(true)) return true;
            u32 rc = kc.GetCertFromXml(xml.span(), (int)id, out, was_text);
            c.done(rc);
            emit(h, -1, true, rc, out.span(), false);
            return true;
        }
        case M_GetSigAlgFromXML: {
            Bytes xml, out;
            bool was_text = true;
            c.xml(0, xml, was_text);
            if (!c.args_ok(true)) return true;
            u32 rc = kc.GetSigAlgFromXml(xml.span(), out, was_text);
            c.done(rc);
            emit(h, -1, true, rc, out.span(), false);
            return true;
        }
        case M_XMLFinalize: st.clear_error(); h.put_int(-1, 0); return true;
        case M_TSASetUrl: {
            Bytes url;
            c.name(0, url);
            if (!c.args_ok(false)) return true;
            u32 rc = kc.TsaSetUrl(url.span());
            c.done(rc);
            h.put_int(-1, rc);
            return true;
        }
        case M_GetTimeFromSig: {
            u32 flags, sid = 0;
            if (!c.num(1, flags, "GetTimeFromSig: flags")) { h.put_text(-1, Span("")); return true; }
            c.num(2, sid, "GetTimeFromSig: signID");
            Bytes sig;
            c.data(0, sig);
            if (!c.args_ok(true)) return true;
            i64 t = 0;
            u32 rc = kc.GetTimeFromSig(sig.span(), flags, (int)sid, t);
            c.done(rc);
            if (rc != KCR_OK) { h.put_text(-1, Span("")); return true; }
            char num[24]; int k = 0; u64 v = (u64)t;
            if (!v) num[k++] = '0';
            while (v) { num[k++] = (char)('0' + v % 10); v /= 10; }
            Bytes txt;
            while (k) txt.push((u8)num[--k]);
            h.put_text(-1, txt.span());
            return true;
        }
        case M_SetProxy: {
            u32 flags = 0;
            c.num(0, flags, "SetProxy: flags");
            Bytes a, p, u, w;
            c.name(1, a); c.name(2, p); c.name(3, u); c.name(4, w);
            if (!c.args_ok(false)) return true;
            u32 rc = kc.SetProxy(flags, a.span(), p.span(), u.span(), w.span());
            c.done(rc);
            h.put_int(-1, rc);
            return true;
        }
        case M_GetCertFromCMS: {
            u32 sid, flags;
            if (!c.num(1, sid, "GetCertFromCMS: signID") || !c.num(2, flags, "GetCertFromCMS: flags")) { h.put_text(-1, Span("")); return true; }
            Bytes cms, out;
            c.data(0, cms);
            if (!c.args_ok(true)) return true;
            u32 rc = kc.GetCertFromCms(cms.span(), flags, (int)sid, out);
            c.done(rc);
            emit(h, -1, true, rc, out.span(), (flags & KC_OUT_DER) != 0);
            return true;
        }
        case M_SignWSSE: case M_SignWSSEResult: case M_ZipConSign: case M_ZipConVerify: case M_GetCertFromZipFile: {
            st.set_error(WRAP_NOT_IMPLEMENTED_, "Эта возможность не входит в текущую сборку NEKalkan.");
            if (m == M_SignWSSE || m == M_ZipConSign) h.put_int(-1, WRAP_NOT_IMPLEMENTED_);
            else h.put_text(-1, Span(""));
            return true;
        }
        default:
            return false;
    }
}

}  // namespace nek
