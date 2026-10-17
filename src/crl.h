// NEKalkan — списки отозванных сертификатов (CRL): разбор, проверка подписи УЦ, поиск серийного номера.
#pragma once
#include "rt.h"
#include "x509.h"

namespace nek {

struct Crl {
    Bytes der;
    Span tbs;
    Span issuer;                // Name (TLV)
    Span sig_alg_oid, sig_bits;
    i64 this_update = 0, next_update = 0;
    bool has_next = false;
    bool is_delta = false;      // есть расширение deltaCRLIndicator (2.5.29.27)
    Span revoked;               // содержимое SEQUENCE OF revokedCertificates (может быть пустым)

    bool load(Span data);       // DER, PEM или Base64
    // Подпись CRL ключом сертификата УЦ
    bool verify(const Cert& issuer) const;
    // Серийный номер (содержимое INTEGER) в списке отозванных?
    bool is_revoked(Span serial, i64* revocation_time = 0) const;
};

}  // namespace nek
