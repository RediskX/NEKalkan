// NEKalkan — «ядро-совместимость» с KalkanCrypt: контекст, флаги, форматы, коды ошибок.
//
// Класс Kalkan повторяет поведение функций KalkanCrypt SDK (SignData, VerifyData, SignXML, X509LoadCertificateFromFile …),
// снятое с настоящей KalkanCrypt.dll. Все методы принимают и возвращают байты (UTF-8, где это текст) и возвращают код KCR_*.
#pragma once
#include "rt.h"
#include "keystore.h"
#include "x509.h"

namespace nek {

enum KcFlags : u32 {
    KC_SIGN_DRAFT = 0x1, KC_SIGN_CMS = 0x2, KC_IN_PEM = 0x4, KC_IN_DER = 0x8, KC_IN_BASE64 = 0x10, KC_IN2_BASE64 = 0x20,
    KC_DETACHED_DATA = 0x40, KC_WITH_CERT = 0x80, KC_WITH_TIMESTAMP = 0x100, KC_OUT_PEM = 0x200, KC_OUT_DER = 0x400,
    KC_OUT_BASE64 = 0x800, KC_PROXY_OFF = 0x1000, KC_PROXY_ON = 0x2000, KC_PROXY_AUTH = 0x4000, KC_IN_FILE = 0x8000,
    KC_NOCHECKCERTTIME = 0x10000, KC_HASH_SHA256 = 0x20000, KC_HASH_GOST95 = 0x40000, KC_GET_OCSP_RESPONSE = 0x80000,
    KC_HASH_GOST15_256 = 0x100000, KC_HASH_GOST15_512 = 0x200000,
};

enum KcConst : u32 {
    KCST_PKCS12 = 0x1, KCST_KZIDCARD = 0x2, KCST_KAZTOKEN = 0x4, KCST_ETOKEN72K = 0x8, KCST_JACARTA = 0x10,
    KCST_X509CERT = 0x20, KCST_AKEY = 0x40, KCST_ETOKEN5110 = 0x80,
    KC_CERT_DER = 0x101, KC_CERT_PEM = 0x102, KC_CERT_B64 = 0x104,
    KC_CERT_CA = 0x201, KC_CERT_INTERMEDIATE = 0x202, KC_CERT_USER = 0x204,
    KC_USE_NOTHING = 0x401, KC_USE_CRL = 0x402, KC_USE_OCSP = 0x404,
};

// Прочие коды: ошибки OpenSSL, которые KalkanCrypt возвращает «как есть»
enum : u32 {
    KC_ERR_GOST_VERIFY = 0x8006E07B,   // GOST_EC_VERIFY: signature mismatch
    KC_ERR_CMS_VERIFY = 0x2E09A09E,    // CMS_SignerInfo_verify_content: verification failure
    KC_ERR_ASN1_TAG = 0x0D0680A8,      // asn1_check_tlen: wrong tag
    KC_ERR_CMS_NO_CONTENT = 0x2E06307F, // check_content: no content
};

class Kalkan {
public:
    Kalkan();
    ~Kalkan();

    // ---- служебное ----
    u32 Init();
    void Finalize();
    bool initialized() const { return inited_; }
    u32 last_code() const { return last_code_; }
    const Bytes& log() const { return log_; }
    void ClearLog() { log_.clear(); last_code_ = 0; }

    // ---- хранилище ключей и сертификатов ----
    u32 LoadKeyStore(u32 storage, Span password, Span container_utf8, Span alias);
    u32 LoadCertFromFile(Span path_utf8, u32 cert_type);
    u32 LoadCertFromBuffer(Span data, u32 flag);
    u32 ExportCert(Span alias, u32 flag, Bytes& out);
    u32 CertGetInfo(Span cert, u32 prop_id, Bytes& out);
    u32 ValidateCert(Span cert, u32 valid_type, Span valid_path_utf8, i64 check_time, u32 flags, Bytes& info, Bytes& ocsp_response);
    u32 GetCertificatesList(Bytes& out, u32& count);
    u32 GetTokens(u32 storage, Bytes& out, u32& count);

    // ---- хэш и подпись данных ----
    u32 HashData(Span algorithm, u32 flags, Span in, Bytes& out);
    u32 SignHash(Span alias, u32 flags, Span hash, Bytes& out);
    u32 SignData(Span alias, u32 flags, Span in, Span in_sign, Bytes& out);
    u32 VerifyData(Span alias, u32 flags, Span in_data, Span in_sign, int cert_id, Bytes& out_data, Bytes& info, Bytes& out_cert);
    u32 GetCertFromCms(Span cms, u32 flags, int sign_id, Bytes& out);
    u32 GetTimeFromSig(Span data, u32 flags, int sig_id, i64& unix_time);

    // ---- XML ----
    // utf8_text = true — XML пришёл строкой 1С (уже UTF-8): декларация encoding= игнорируется; BLOB/файл — false.
    u32 SignXml(Span alias, u32 flags, Span node_id, Span parent_node, Span parent_ns, Span in, Bytes& out, bool utf8_text = false);
    u32 VerifyXml(Span alias, u32 flags, Span in, Bytes& info, bool utf8_text = false);
    u32 GetCertFromXml(Span xml, int sign_id, Bytes& out, bool utf8_text = false);
    u32 GetSigAlgFromXml(Span xml, Bytes& out, bool utf8_text = false);

    // ---- настройки ----
    u32 TsaSetUrl(Span url);
    u32 SetProxy(u32 flags, Span addr, Span port, Span user, Span pass);

    // доступ для тестов и моста к платформе
    const SignKey& key() const { return key_; }
    bool has_key() const { return has_key_; }

private:
    bool inited_ = false;
    SignKey key_;
    bool has_key_ = false;
    Vec<Cert*> ca_, inter_, user_;
    Bytes log_;
    u32 last_code_ = 0;
    Bytes tsa_url_;

    u32 fail(u32 code, const char* op, const char* text);
    void note(const char* op, const char* text = "OK");
    void clear_certs();
    static bool parse_cert(Span in, Cert& c);
    u32 check_signer(const SignKey& k, u32 flags, bool need_chain);
    u32 chain_check(const Cert& c, u32 flags);
    u32 decode_input(Span in, u32 flags, bool is_signature, Bytes& out, const char* op);
    void encode_out(Span data, u32 flags, bool is_cms, Bytes& out);
    u32 encode_cert(const Cert& c, u32 out_flags, Bytes& out);
    const Cert* signer_cert_for_raw(Span, int) const;
};

// Название ошибки/расшифровка по коду (русские и английские тексты как у KalkanCrypt)
const char* kc_error_text(u32 code);

}  // namespace nek
