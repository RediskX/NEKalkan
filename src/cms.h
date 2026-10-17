// NEKalkan — CMS / PKCS#7 SignedData (CAdES-BES): разбор, проверка и формирование.
#pragma once
#include "rt.h"
#include "asn1.h"
#include "x509.h"
#include "keystore.h"

namespace nek {

struct SignerResult {
    char digest_oid[64];
    char sig_oid[64];
    int digest_ok;      // 1/0, -1 — не проверялось
    int signature_ok;
    int chain_ok;
    int time_ok;
    const char* state;  // "ok", "failed", "no_signed_attrs", "bad_signed_attrs", "no_certificate", "unsupported_oid", ...
    int cert_index;     // индекс сертификата подписанта в CmsMessage::certs или -1
    bool has_time;
    i64 signing_time;   // из атрибута signingTime
    bool has_tsa;       // есть метка времени (unsignedAttrs id-aa-timeStampToken)
    int cades_ok;       // проверка signingCertificateV2: 1 — хэш сертификата совпал, 0 — нет, -1 — атрибута нет
    u32 chain_rc;       // код проверки цепочки (KCR_*), 0 — успешно или не проверялась
    bool has_tsa_time;  // время из токена метки времени (TSTInfo.genTime)
    i64 tsa_time;
};

class CmsMessage {
public:
    Bytes der;                       // нормализованный DER
    Bytes content;                   // содержимое (встроенное или внешнее)
    bool has_embedded = false;
    char econtent_type[64];
    Vec<Cert*> certs;
    Vec<SignerResult> signers;
    Vec<Span> signer_infos;          // TLV SignerInfo
    int fail_line = 0;               // диагностика: строка cms.cpp, на которой остановился parse()

    ~CmsMessage();
    // Разбор структуры (без проверки подписей). Принимает DER или BER.
    bool parse(Span cms);
    // Проверка всех подписантов. detached — внешнее содержимое (если нет встроенного).
    // anchors/pool — доверенные корни и промежуточные сертификаты; check_time = 0 — не проверять срок
    // (кроме случая, когда flags не содержит CHAIN_NO_TIME и есть anchors: тогда сроки проверяются «сейчас»).
    bool verify(const Bytes* detached, const Cert* const* anchors, size_t anchors_n, const Cert* const* pool, size_t pool_n,
                i64 check_time, u32 chain_flags);
};

// Параметры подписи CMS.
struct CmsSignOptions {
    bool detached = false;
    bool with_cert = true;
    i64 signing_time = 0;            // 0 — сейчас
    const Cert* const* extra_certs = 0;
    size_t extra_n = 0;
    Span precomputed_digest;         // если задан — message-digest берётся отсюда (SignHash); содержимое не встраивается
};

// Формирует CMS SignedData. data — подписываемое содержимое.
bool cms_sign(const SignKey& key, Span data, const CmsSignOptions& opt, Bytes& out);

// Добавляет ещё одну подпись в существующий CMS (мультиподпись). Для detached-CMS нужны подписанные данные.
bool cms_add_signer(Span existing_cms, const SignKey& key, Span detached_data, const CmsSignOptions& opt, Bytes& out);

// Подпись готового хэша (RAW): r||s для ГОСТ, PKCS#1 v1.5 (SHA-256) для RSA.
bool sign_prehashed(const SignKey& key, Span digest, Bytes& sig);

// Только подпись «сырая»: RAW как в ЭСФ — подпись хэша данных (r||s для ГОСТ, PKCS#1 для RSA).
bool raw_sign(const SignKey& key, Span data, Bytes& sig);
bool raw_verify(const Cert& cert, Span data, Span sig, bool prehashed = false);

}  // namespace nek
