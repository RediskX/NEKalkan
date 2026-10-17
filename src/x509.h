// NEKalkan — сертификаты X.509: разбор, имена, расширения, проверка подписи и цепочки.
#pragma once
#include "rt.h"
#include "asn1.h"
#include "hash.h"

namespace nek {

// Алгоритмы (OID НУЦ РК и общие).
extern const char* const OID_KZ_GOST2015_KEY;      // 1.2.398.3.10.1.1.2.2
extern const char* const OID_KZ_GOST2015_HASH256;  // 1.2.398.3.10.1.1.2.2.1
extern const char* const OID_KZ_GOST2015_HASH512;  // 1.2.398.3.10.1.3.3
extern const char* const OID_KZ_GOST2015_SIG;      // 1.2.398.3.10.1.1.2.3.2
extern const char* const OID_KZ_LEGACY_SIG;        // 1.2.398.3.10.1.1.1.1
extern const char* const OID_KZ_LEGACY_SIG_CERT;   // 1.2.398.3.10.1.1.1.2
extern const char* const OID_KZ_LEGACY_HASH;       // 1.2.398.3.10.1.3.1
extern const char* const OID_RSA_ENCRYPTION;       // 1.2.840.113549.1.1.1

struct Cert {
    Bytes der;                       // владеет копией DER
    Span tbs;                        // TLV tbsCertificate
    Span serial;                     // содержимое INTEGER
    Span tbs_sig_alg;                // AlgorithmIdentifier (TLV) внутри tbs
    Span issuer, subject;            // Name (TLV)
    i64 not_before = 0, not_after = 0;
    Span spki;                       // TLV SubjectPublicKeyInfo
    Span spki_alg_oid;               // содержимое OID
    Span spki_params;                // TLV параметров (может быть пусто)
    Span spki_bits;                  // содержимое BIT STRING (без байта unused)
    Span sig_alg_oid;                // внешний signatureAlgorithm: содержимое OID
    Span sig_alg_params;             // TLV параметров (может быть пусто)
    Span sig_bits;                   // подпись (без байта unused)
    Span extensions;                 // содержимое SEQUENCE расширений (пусто, если нет)

    // Часто нужные расширения
    bool has_bc = false, bc_ca = false;
    long bc_pathlen = -1;
    bool has_ku = false;
    u32 ku = 0;                      // бит i: i-й бит keyUsage (0 = digitalSignature … 5 = keyCertSign, 6 = cRLSign)

    bool load(Span der_bytes);       // DER (копируется)
    bool find_ext(const char* oid, Span& value, bool* critical = 0) const;   // value — содержимое OCTET STRING
    bool is_self_issued() const { return issuer.eq(subject); }
};

// Значение первого атрибута Name с данным OID → UTF-8. false, если нет.
bool name_get(Span name_tlv, const char* oid, Bytes& out_utf8);
// Строка значения атрибута (TLV значения) → UTF-8.
bool asn_string_to_utf8(u32 tag, Span val, Bytes& out);

// Открытый ключ ГОСТ: содержимое точки (X||Y) из BIT STRING по правилам НУЦ РК.
bool gost_point_from_spki_bits(Span bits, Span& point);

// Проверка подписи сертификата cert открытым ключом issuer (ГОСТ 2015, RSA). false — подпись неверна/неподдержана.
// unsupported (если задан) = true, когда алгоритм не поддержан (а не просто подпись не сошлась).
bool cert_verify_signature(const Cert& cert, const Cert& issuer, bool* unsupported = 0);

// Проверка подписи произвольных данных ключом из сертификата.
// sig_alg_oid — OID алгоритма подписи (из SignerInfo или сертификата), digest_alg_oid — из SignerInfo (может быть пуст).
bool verify_with_cert_key(const Cert& cert, Span sig_alg_oid, Span digest_alg_oid, Span data, Span sig, bool* unsupported = 0);

enum ChainFlags : u32 {
    CHAIN_NO_TIME = 1,                // не проверять сроки (KC_NOCHECKCERTTIME)
};

// Построить и проверить цепочку cert → … → якорь из anchors (корни). pool — промежуточные.
// check_time — момент проверки (Unix, 0 = сейчас). Возвращает код KCR_*: 0 — всё хорошо.
u32 chain_validate(const Cert& cert, const Cert* const* pool, size_t pool_n, const Cert* const* anchors, size_t anchors_n,
                   i64 check_time, u32 flags);

}  // namespace nek
