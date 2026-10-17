// NEKalkan — хэш-функции: SHA-1, SHA-2 (256/384/512), Стрибог (ГОСТ Р 34.11-2012, 256/512), HMAC.
#pragma once
#include "rt.h"

namespace nek {

enum HashAlg : int {
    H_NONE = 0,
    H_SHA1 = 1,
    H_SHA256 = 2,
    H_SHA384 = 3,
    H_SHA512 = 4,
    H_STREEBOG256 = 5,
    H_STREEBOG512 = 6,
    H_GOST94 = 7,            // ГОСТ Р 34.11-94, казахстанская презентация (только hash_data)
};

size_t hash_size(HashAlg a);    // размер дайджеста в байтах
size_t hash_block(HashAlg a);   // размер блока (для HMAC)

struct HashCtx {
    HashAlg alg;
    u64 total;                   // всего подано байт
    size_t blen;                 // заполнение буфера
    u8 buf[128];
    union {
        u32 s32[8];              // SHA-1 (5) / SHA-256 (8)
        u64 s64[8];              // SHA-384/512
        struct { u64 h[8]; u64 n[8]; u64 sigma[8]; } gost;   // Стрибог
    } st;
};

void hash_init(HashCtx& c, HashAlg a);
void hash_update(HashCtx& c, const void* data, size_t len);
void hash_final(HashCtx& c, u8* out);      // out: hash_size(alg) байт

// Одним вызовом. Стрибог возвращает дайджест в порядке байт, принятом в НУЦ РК
// (то есть «как у Калкана до разворота в little-endian при подписи»).
void hash_data(HashAlg a, const void* data, size_t len, u8* out);
inline void hash_data(HashAlg a, Span s, u8* out) { hash_data(a, s.p, s.n, out); }

void hmac(HashAlg a, Span key, Span data, u8* out);

}  // namespace nek
