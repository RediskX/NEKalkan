// NEKalkan — XMLDSig (enveloped и по ссылке на Id) с ГОСТ Р 34.10-2015 / RSA, как в KalkanCrypt.
#pragma once
#include "rt.h"
#include "xml.h"
#include "keystore.h"

namespace nek {

// Флаги KalkanCrypt для SignXML (каноникализация ссылки и SignedInfo)
enum : u32 {
    KC_XML_INCL_C14N = 0x01000001, KC_XML_INCL_C14NCOMMENT = 0x01000002,
    KC_XML_INCL_C14N11 = 0x01000004, KC_XML_INCL_C14N11COMMENT = 0x01000008,
    KC_XML_EXCL_C14N = 0x01000010, KC_XML_EXCL_C14NCOMMENT = 0x01000020,
    KC_XMLC_INCL_C14N = 0x01000040, KC_XMLC_INCL_C14NCOMMENT = 0x01000080,
    KC_XMLC_INCL_C14N11 = 0x01000100, KC_XMLC_INCL_C14N11COMMENT = 0x01000200,
    KC_XMLC_EXCL_C14N = 0x01000400, KC_XMLC_EXCL_C14NCOMMENT = 0x01000800,
};

struct XmlSignOptions {
    u32 flags = 0;
    Span sign_node_id;       // Id элемента, который подписывается (пусто — весь документ)
    Span parent_node;        // имя элемента (локальное), в который кладётся Signature (пусто — корень)
    Span parent_ns;          // пространство имён этого элемента
    bool utf8_text = false;  // вход — текст, уже приведённый к UTF-8 (объявленную кодировку игнорировать)
};

// Подписать XML. KCR_OK либо код ошибки (KCR_XMLPARSEERROR, KCR_XMLSETSIGNERROR, KCR_SIGN_ERROR ...).
u32 xml_sign(const SignKey& key, Span xml, const XmlSignOptions& opt, Bytes& out);

struct XmlSigInfo {
    int number = 0;                  // порядковый номер подписи в документе (с 1)
    Bytes id;                        // атрибут Id элемента Signature
    Bytes cert_der;                  // сертификат из KeyInfo (может быть пуст)
    int digest_ok = 0;               // все Reference сошлись
    int signature_ok = 0;
    int chain_ok = -1;               // -1 — не проверялось
    int time_ok = -1;
    Bytes sig_method;                // URI SignatureMethod
};

struct XmlVerifyOptions {
    const Cert* const* anchors = 0; size_t anchors_n = 0;     // доверенные корни
    const Cert* const* pool = 0; size_t pool_n = 0;           // промежуточные
    i64 check_time = 0;
    u32 chain_flags = 0;
    const Cert* signer = 0;          // если задан — проверять этим сертификатом, а не из KeyInfo
    bool utf8_text = false;
};

// Проверка всех подписей. results — по порядку документа. Возвращает KCR_OK, если разбор удался (результат по каждой подписи — внутри);
// KCR_XMLPARSEERROR — не XML; KCR_NOSIGNFOUND — нет подписей.
u32 xml_verify(Span xml, const XmlVerifyOptions& opt, Vec<XmlSigInfo*>& results);

// Сертификат n-й подписи (с 0) и алгоритм подписи (URI SignatureMethod).
u32 xml_get_cert(Span xml, int index, Bytes& cert_der, bool utf8_text = false);
u32 xml_get_sigalg(Span xml, Bytes& uri, bool utf8_text = false);

}  // namespace nek
