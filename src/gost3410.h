// NEKalkan — ГОСТ Р 34.10-2012 (СТ РК ГОСТ Р 34.10-2015): подпись и проверка на кривых ТК26.
//
// Конвенции байтов — как у НУЦ РК (см. kalkan_verify.py):
//   открытый ключ в сертификате : X || Y, каждая половина little-endian (size байт на координату);
//   подпись                     : r || s, каждая половина little-endian;
//   дайджест                    : вывод hash_data(Стрибог) как есть; число e — его little-endian чтение;
//   закрытый ключ               : size байт big-endian .
#pragma once
#include "rt.h"

namespace nek {

struct GostCurve;

// Идентификаторы кривых (порядок совпадает с gost_curves.inc)
enum { CURVE_TC26_256_A = 0, CURVE_TC26_512_A = 1, CURVE_CRYPTOPRO_A = 2, CURVE_CRYPTOPRO_B = 3, CURVE_CRYPTOPRO_C = 4 };
const GostCurve* gost_curve_id(int id);
// size: 32 — id-tc26-gost-3410-2012-256-paramSetA, 64 — id-tc26-gost-3410-12-512-paramSetA.
const GostCurve* gost_curve(int size);
int gost_curve_size(const GostCurve* c);

bool gost3410_verify(const GostCurve* c, Span pub_xy_le, Span digest, Span sig_rs_le);
bool gost3410_sign(const GostCurve* c, Span priv_be, Span digest, u8* sig_rs_le /* 2*size */);
// Тот же алгоритм с заданным k (big-endian, size байт) — для проверки на тестовых векторах.
bool gost3410_sign_k(const GostCurve* c, Span priv_be, Span digest, Span k_be, u8* sig_rs_le);
// Открытый ключ по закрытому: X||Y, каждая половина big-endian (порядок байт как у закрытого ключа).
bool gost3410_public_be(const GostCurve* c, Span priv_be, u8* xy_be /* 2*size */);

}  // namespace nek
