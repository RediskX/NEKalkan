// NEKalkan — ключ подписи и контейнер PKCS#12.
#pragma once
#include "rt.h"
#include "x509.h"
#include "rsa.h"

namespace nek {

enum KeyType { KEY_NONE = 0, KEY_GOST2015 = 1, KEY_RSA = 2 };

struct SignKey {
    KeyType type = KEY_NONE;
    int gost_size = 0;               // 32 или 64 (длина половины подписи/хэша)
    Bytes gost_priv;                 // закрытый ключ ГОСТ, big-endian
    RsaPrivKey rsa;
    Cert* cert = 0;                  // сертификат владельца ключа (принадлежит SignKey)
    Vec<Cert*> others;               // остальные сертификаты контейнера (цепочка)
    Bytes alias;                     // метка сертификата (friendlyName, если есть)

    SignKey() {}
    ~SignKey() { reset(); }
    SignKey(const SignKey&) = delete;
    SignKey& operator=(const SignKey&) = delete;
    void reset();
};

// Загрузка PKCS#12. Пароль — UTF-8. Возвращает KCR_OK или код ошибки:
// KCR_ERROR_READ_PKCS12, KCR_INVALIDPASSWORD, KCR_KEY_NOT_FOUND, KCR_CERTNOTFOUND, KCR_MEMORY_ERROR.
u32 p12_load(Span data, Span password_utf8, SignKey& out);

}  // namespace nek
