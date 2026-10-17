// NEKalkan — методы компоненты 1С: таблица, константы, диспетчер.
#include "api1c.h"
#include "codec.h"

namespace nek {

#include "api_constants.inc"

static const u32 WRAP_NOT_IMPLEMENTED_ = 0x0A51000C;     // возможность не входит в эту сборку

const MethodInfo API_METHODS[] = {
    {"Init", "Инициализировать", 0},
    {"Finalize", "Завершить", 0},
    {"SetKalkanPath", "УстановитьПутьКалкан", 1},
    {"SetKalkanDirectory", "УстановитьКаталогКалкан", 1},
    {"GetKalkanPath", "ПолучитьПутьКалкан", 0},
    {"LoadKeyStore", "ЗагрузитьХранилищеКлючей", 4},
    {"X509ExportCertificateFromStore", "ЭкспортСертификатаИзХранилища", 3},
    {"ExportCertificate", "ЭкспортСертификата", 2},
    {"SignData", "ПодписатьДанные", 4},
    {"SignDataText", "ПодписатьДанныеВСтроку", 4},
    {"SignDataBlob", "ПодписатьДанныеВБайты", 4},
    {"X509CertificateGetInfo", "ПолучитьИнформациюСертификата", 3},
    {"CertificateGetInfo", "ПолучитьСвойствоСертификата", 2},
    {"GetLastErrorString", "ПолучитьПоследнююОшибку", 2},
    {"GetLastErrorText", "ПолучитьТекстПоследнейОшибки", 0},
    {"GetLastErrorCode", "ПолучитьКодПоследнейОшибки", 0},
    {"SetStringEncoding", "УстановитьКодировкуСтрок", 1},
    {"GetStringEncoding", "ПолучитьКодировкуСтрок", 0},
    {"GetWrapperVersion", "ПолучитьВерсиюОбертки", 0},
    {"GetDefaultKalkanPath", "ПолучитьПутьКалканПоУмолчанию", 0},
    {"SignDataResult", "ПодписатьДанныеРезультатом", 4},
    {"SignDataResult3", "ПодписатьДанныеРезультатом3", 3},
    {"GetMethodList", "ПолучитьСписокМетодов", 0},
    {"GetPropertyList", "ПолучитьСписокСвойств", 0},
    {"GetErrorName", "ПолучитьИмяОшибки", 1},
    {"GetLastErrorFull", "ПолучитьПоследнююОшибкуПолностью", 0},
    {"SetKeyStoreTempDirectory", "УстановитьВременныйКаталогКлючей", 1},
    {"GetKeyStoreTempDirectory", "ПолучитьВременныйКаталогКлючей", 0},
    {"LoadKeyStoreSafe", "ЗагрузитьХранилищеКлючейБезопасно", 4},
    {"GetTokens", "ПолучитьТокены", 1},
    {"GetCertificatesList", "ПолучитьСписокСертификатов", 0},
    {"X509LoadCertificateFromFile", "ЗагрузитьСертификатИзФайла", 2},
    {"X509LoadCertificateFromBuffer", "ЗагрузитьСертификатИзБуфера", 2},
    {"X509ValidateCertificate", "ПроверитьСертификат", 7},
    {"X509ValidateCertificateResult", "ПроверитьСертификатРезультатом", 4},
    {"HashData", "ХешироватьДанные", 4},
    {"HashDataResult", "ХешироватьДанныеРезультатом", 3},
    {"SignHash", "ПодписатьХеш", 4},
    {"SignHashResult", "ПодписатьХешРезультатом", 3},
    {"SignXML", "ПодписатьXML", 7},
    {"SignXMLResult", "ПодписатьXMLРезультатом", 6},
    {"SignXMLNative", "ПодписатьXMLNative", 7},
    {"SignXMLNativeResult", "ПодписатьXMLNativeРезультатом", 6},
    {"VerifyData", "ПроверитьДанные", 8},
    {"VerifyDataResult", "ПроверитьДанныеРезультатом", 4},
    {"VerifyXML", "ПроверитьXML", 4},
    {"VerifyXMLResult", "ПроверитьXMLРезультатом", 3},
    {"GetCertFromXML", "ПолучитьСертификатИзXML", 2},
    {"GetSigAlgFromXML", "ПолучитьАлгоритмПодписиИзXML", 1},
    {"XMLFinalize", "ЗавершитьXML", 0},
    {"TSASetUrl", "УстановитьАдресTSA", 1},
    {"GetTimeFromSig", "ПолучитьВремяИзПодписи", 3},
    {"SetProxy", "УстановитьПрокси", 5},
    {"GetCertFromCMS", "ПолучитьСертификатИзCMS", 3},
    {"SignWSSE", "ПодписатьWSSE", 5},
    {"SignWSSEResult", "ПодписатьWSSERезультатом", 4},
    {"ZipConVerify", "ПроверитьZipКонтейнер", 2},
    {"ZipConSign", "ПодписатьZipКонтейнер", 5},
    {"GetCertFromZipFile", "ПолучитьСертификатИзZip", 3},
    {"GetLastError", "ПолучитьПоследнююОшибкуКод", 0},
};
const int API_METHOD_COUNT = (int)(sizeof(API_METHODS) / sizeof(API_METHODS[0]));

const int API_CONST_COUNT = (int)(sizeof(API_CONSTANTS) / sizeof(API_CONSTANTS[0]));
bool api_const(int i, const char** name, i32* value) {
    if (i < 0 || i >= API_CONST_COUNT) return false;
    *name = API_CONSTANTS[i].name;
    *value = API_CONSTANTS[i].value;
    return true;
}

bool api_param_has_default(int m, int p) {
    switch (m) {
        case M_LoadKeyStore: case M_LoadKeyStoreSafe: case M_SignData: case M_SignDataText: case M_SignDataBlob: case M_SignDataResult:
            return p == 3;
        case M_X509ValidateCertificate: return p == 5 || p == 6;
        case M_HashData: case M_SignHash: return p == 3;
        case M_SignXML: case M_SignXMLNative: return p == 6;
        case M_VerifyData: return p == 4 || p == 5 || p == 7;
        case M_VerifyXML: return p == 3;
        case M_SignWSSE: return p == 4;
        default: return false;
    }
}

const char* api_error_name(u32 code) {
    for (int i = 0; i < API_CONST_COUNT; ++i) {
        const char* n = API_CONSTANTS[i].name;
        if ((u32)API_CONSTANTS[i].value != code) continue;
        if (n[0] == 'K' && n[1] == 'C' && n[2] == 'R' && n[3] == '_') return n;
        if (n[0] == 'W' && n[1] == 'R' && n[2] == 'A' && n[3] == 'P') return n;
    }
    if (code == WRAP_NOT_IMPLEMENTED_) return "WRAP_NOT_IMPLEMENTED";
    if (code == 0x2E09A09Eu) return "OPENSSL_CMS_VERIFICATION_FAILURE";
    if (code == 0x8006E07Bu) return "OPENSSL_GOST_SIGNATURE_MISMATCH";
    if (code == 0x0D0680A8u) return "OPENSSL_ASN1_WRONG_TAG";
    return "UNKNOWN_ERROR";
}

static bool ieq(Span a, const char* b) {
    size_t i = 0;
    for (; i < a.n; ++i) {
        char c = (char)a.p[i];
        if (c >= 'a' && c <= 'z') c = (char)(c - 32);
        if (!b[i] || c != b[i]) return false;
    }
    return b[i] == 0;
}

bool api_parse_encoding(Span name, int& enc) {
    if (ieq(name, "UTF-8") || ieq(name, "UTF8")) { enc = ENC_UTF8; return true; }
    if (ieq(name, "CP1251") || ieq(name, "1251") || ieq(name, "WINDOWS-1251")) { enc = ENC_CP1251; return true; }
    if (ieq(name, "ACP")) { enc = ENC_ACP; return true; }
    return false;
}

const char* api_encoding_name(int enc) {
    return enc == ENC_CP1251 ? "CP1251" : enc == ENC_ACP ? "ACP" : "UTF-8";
}

// ---- состояние ошибок -------------------------------------------------------------------------

void ApiState::set_error(u32 code, const char* text) {
    err_code = code;
    ++err_serial;
    err_text.clear();
    err_text.append_str(text ? text : "");
}

void ApiState::set_error_from_engine(u32 code, size_t log_mark) {
    err_code = code;
    ++err_serial;
    err_text.clear();
    const Bytes& lg = kc.log();
    if (log_mark < lg.n) err_text.append(lg.p + log_mark, lg.n - log_mark);
    while (err_text.n && (err_text.p[err_text.n - 1] == '\n' || err_text.p[err_text.n - 1] == '\r')) err_text.n--;
    if (err_text.p) err_text.p[err_text.n] = 0;
    if (!err_text.n) err_text.append_str(kc_error_text(code));
}

}  // namespace nek
