// NEKalkan — RSA: проверка и подпись PKCS#1 v1.5 (SHA-1/256/384/512).
#pragma once
#include "rt.h"
#include "hash.h"

namespace nek {

// Открытый ключ: модуль n и экспонента e — big-endian без ведущих нулей (допустимы ведущие нули).
bool rsa_pkcs1_verify(Span n_be, Span e_be, HashAlg alg, Span digest, Span sig);

struct RsaPrivKey {
    Bytes n, e, d, p, q, dp, dq, qinv;   // все big-endian
};

// Подпись PKCS#1 v1.5 по готовому дайджесту. Нужны n, e, p, q, dp, dq, qinv (CRT).
bool rsa_pkcs1_sign(const RsaPrivKey& k, HashAlg alg, Span digest, Bytes& sig);

// Префикс DigestInfo (DER) для хэша; пусто — хэш не поддержан.
Span rsa_digest_info_prefix(HashAlg alg);

}  // namespace nek
