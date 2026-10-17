// NEKalkan — устаревшие ГОСТ НУЦ РК: СТ РК ГОСТ Р 34.311-95 (≈ ГОСТ Р 34.11-94, казахстанская презентация)
// и ГОСТ 28147-89. Подпись 34.10-2001 проверяется общим кодом gost3410.cpp на кривых КриптоПро A/B/C.
#pragma once
#include "rt.h"

namespace nek {

enum Gost94Sbox { GOST94_TEST = 0, GOST94_CRYPTOPRO = 1 };

// ГОСТ 28147-89, простая замена, один блок (ключ 32 байта, блок 8 байт, порядок байт big-endian).
void gost28147_encrypt_block(const u8 key[32], const u8 in[8], u8 out[8], Gost94Sbox sbox);

// ГОСТ Р 34.11-94: «академический» порядок байт результата.
void gost341194(Span data, u8 out[32], Gost94Sbox sbox = GOST94_TEST);
// Казахстанская презентация (как HashData "Gost34311_95" у KalkanCrypt): результат в обратном порядке байт,
// для пустого ввода — три шага с нулевыми блоками.
void gost341194_kz(Span data, u8 out[32], Gost94Sbox sbox = GOST94_TEST);

// Кривая ГОСТ Р 34.10-2001 по OID набора параметров (1.2.398.3.10.1.1.1.1.N, 1.2.643.2.2.35.N, 1.2.643.2.2.36.N); -1 — неизвестен.
int gost2001_curve_by_oid(Span oid_content);

}  // namespace nek
