// NEKalkan — слой методов компоненты 1С: таблица методов, константы, диспетчер вызовов.
//
// Диспетчер не знает про Native API: параметры и результаты передаются через ApiHost. Мост к платформе (native1c.cpp)
// реализует ApiHost поверх tVariant, тесты — поверх простого массива значений.
#pragma once
#include "rt.h"
#include "kalkan.h"

namespace nek {

#define NEK_VERSION "1.0.0"

struct MethodInfo {
    const char* en;
    const char* ru;
    int nparams;
};

extern const MethodInfo API_METHODS[];
extern const int API_METHOD_COUNT;

extern const int API_CONST_COUNT;
bool api_const(int index, const char** name, i32* value);

// Параметры метода, у которых есть значение по умолчанию (пустая строка) — выходные BYREF-параметры.
bool api_param_has_default(int method, int param);

// Источник параметров и приёмник результатов.
class ApiHost {
public:
    virtual ~ApiHost() {}
    virtual int arg_count() = 0;
    // Число (целое); false — параметр не число.
    virtual bool arg_int(int i, i64& v) = 0;
    // Текст «имя/путь/пароль»: всегда UTF-8, независимо от выбранной кодировки обмена.
    virtual bool arg_name(int i, Bytes& out) = 0;
    // Данные: строка в выбранной кодировке обмена (по умолчанию UTF-8) или BLOB — байты как есть.
    virtual bool arg_data(int i, Bytes& out) = 0;
    // XML: строка 1С → UTF-8 (was_text = true), BLOB → байты как есть (was_text = false).
    virtual bool arg_xml(int i, Bytes& out, bool& was_text) = 0;
    // Запись результатов: в BYREF-параметр i либо в возвращаемое значение (i < 0).
    virtual bool put_int(int i, i64 v) = 0;
    virtual bool put_text(int i, Span utf8) = 0;      // текст движка (UTF-8) → строка 1С
    virtual bool put_data(int i, Span bytes) = 0;     // данные (содержимое подписи и т.п.): строка в кодировке обмена, а если так не выходит — BLOB
    virtual bool put_blob(int i, Span bytes) = 0;
    // Смена кодировки обмена строк («UTF-8», «CP1251», «ACP»). false — не поддерживается.
    virtual bool set_encoding(Span name) = 0;
    virtual const char* encoding_name() = 0;
};

class ApiState {
public:
    Kalkan kc;
    u32 err_code = 0;            // код последней ошибки (KCR_* / WRAP_*)
    u32 err_serial = 0;          // растёт при каждой записи ошибки (хост узнаёт, что вызов её породил)
    Bytes err_text;              // текст последней ошибки (UTF-8)
    Bytes tmp_dir;

    void clear_error() { err_code = 0; err_text.clear(); }
    void set_error(u32 code, const char* text);
    void set_error_from_engine(u32 code, size_t log_mark);
};

// Выполнить метод №method. Возвращает false — метод не найден/сбой хоста (платформа получит ошибку вызова).
bool api_call(ApiState& st, int method, ApiHost& host);

// Имя константы ошибки по коду (KCR_*/WRAP_*) либо "UNKNOWN_ERROR".
const char* api_error_name(u32 code);

// Кодировка обмена строк между 1С и компонентой.
enum ApiEncoding { ENC_UTF8 = 0, ENC_CP1251 = 1, ENC_ACP = 2 };
// Разбор имени кодировки: «UTF-8», «UTF8», «CP1251», «1251», «ACP» (регистр не важен). false — не поддерживается.
bool api_parse_encoding(Span name, int& enc);
const char* api_encoding_name(int enc);

// Номера методов (совпадают с таблицей KalkanCryptNative1C)
enum ApiMethod {
    M_Init = 0, M_Finalize, M_SetKalkanPath, M_SetKalkanDirectory, M_GetKalkanPath, M_LoadKeyStore,
    M_X509ExportCertificateFromStore, M_ExportCertificate, M_SignData, M_SignDataText, M_SignDataBlob,
    M_X509CertificateGetInfo, M_CertificateGetInfo, M_GetLastErrorString, M_GetLastErrorText, M_GetLastErrorCode,
    M_SetStringEncoding, M_GetStringEncoding, M_GetWrapperVersion, M_GetDefaultKalkanPath, M_SignDataResult,
    M_SignDataResult3, M_GetMethodList, M_GetPropertyList, M_GetErrorName, M_GetLastErrorFull,
    M_SetKeyStoreTempDirectory, M_GetKeyStoreTempDirectory, M_LoadKeyStoreSafe, M_GetTokens, M_GetCertificatesList,
    M_X509LoadCertificateFromFile, M_X509LoadCertificateFromBuffer, M_X509ValidateCertificate,
    M_X509ValidateCertificateResult, M_HashData, M_HashDataResult, M_SignHash, M_SignHashResult, M_SignXML,
    M_SignXMLResult, M_SignXMLNative, M_SignXMLNativeResult, M_VerifyData, M_VerifyDataResult, M_VerifyXML,
    M_VerifyXMLResult, M_GetCertFromXML, M_GetSigAlgFromXML, M_XMLFinalize, M_TSASetUrl, M_GetTimeFromSig,
    M_SetProxy, M_GetCertFromCMS, M_SignWSSE, M_SignWSSEResult, M_ZipConVerify, M_ZipConSign, M_GetCertFromZipFile,
    M_GetLastError,
};

}  // namespace nek
