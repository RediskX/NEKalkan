// NEKalkan — длинная арифметика для ГОСТ Р 34.10 и RSA.
//
// Числа — массивы 64-битных слов little-endian (u64[n]). Модульные операции — в форме
// Монтгомери для нечётного модуля (простые p, q кривых; n, p, q для RSA), поэтому деления нет.
// Реализация НЕ рассчитана на защиту от атак по сторонним каналам (время/кэш).
#pragma once
#include "rt.h"

namespace nek {

const int BN_MAX = 72;                  // слов: до 4608 бит (хватает на RSA-4096)

// ---- простые операции над массивами из n слов ---------------------------------

void bn_zero(u64* r, int n);
void bn_copy(u64* r, const u64* a, int n);
bool bn_is_zero(const u64* a, int n);
int bn_cmp(const u64* a, const u64* b, int n);              // -1, 0, 1
u64 bn_add(u64* r, const u64* a, const u64* b, int n);      // перенос
u64 bn_sub(u64* r, const u64* a, const u64* b, int n);      // заём
int bn_bitlen(const u64* a, int n);
bool bn_bit(const u64* a, int i);
void bn_from_be(u64* r, int n, const u8* be, size_t len);   // len ≤ 8n, старшие слова обнуляются
void bn_to_be(u8* be, size_t len, const u64* a, int n);     // len байт (младшие len байт числа)
void bn_from_le(u64* r, int n, const u8* le, size_t len);
void bn_to_le(u8* le, size_t len, const u64* a, int n);
void bn_mul_full(u64* r, const u64* a, int na, const u64* b, int nb);   // r[na+nb] = a*b
// r = a mod m (a — na слов, m — nm слов, m ≠ 0); r — nm слов. Побитовый метод.
void bn_mod(u64* r, const u64* a, int na, const u64* m, int nm);

// ---- контекст Монтгомери ---------------------------------------------------------

struct Mont {
    int n;                 // число слов модуля (ровно)
    u64 m[BN_MAX];
    u64 m0inv;             // -m^-1 mod 2^64
    u64 rr[BN_MAX];        // R^2 mod m
    u64 one[BN_MAX];       // R mod m (единица в форме Монтгомери)
};

// m — нечётный модуль, n слов (старшее слово ненулевое).
bool mont_init(Mont& c, const u64* m, int n);
void mont_mul(const Mont& c, u64* r, const u64* a, const u64* b);     // r = a*b/R mod m
void mont_sqr(const Mont& c, u64* r, const u64* a);
void mont_add(const Mont& c, u64* r, const u64* a, const u64* b);     // (a+b) mod m
void mont_sub(const Mont& c, u64* r, const u64* a, const u64* b);     // (a-b) mod m
void mont_neg(const Mont& c, u64* r, const u64* a);
void to_mont(const Mont& c, u64* r, const u64* a);                    // a < m
void from_mont(const Mont& c, u64* r, const u64* a);
// r = a^e (в форме Монтгомери, a — тоже в форме Монтгомери); e — ne слов обычного числа.
void mont_pow(const Mont& c, u64* r, const u64* a, const u64* e, int ne);
// Обратный элемент по малой теореме Ферма (модуль — простое). a — в форме Монтгомери.
void mont_inv_prime(const Mont& c, u64* r, const u64* a);

}  // namespace nek
