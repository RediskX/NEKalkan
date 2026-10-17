// NEKalkan — среда выполнения без CRT (Windows x64, clang -ffreestanding).
#include "rt.h"
#include "plat.h"

// ---- функции, которые компилятор вправе вызывать сам -------------------------

extern "C" {

int _fltused = 0;

void* memset(void* dst, int value, size_t count) {
    void* d = dst;
    __asm__ volatile("rep stosb" : "+D"(d), "+c"(count) : "a"(value) : "memory");
    return dst;
}

void* memcpy(void* dst, const void* src, size_t count) {
    void* d = dst;
    const void* s = src;
    __asm__ volatile("rep movsb" : "+D"(d), "+S"(s), "+c"(count) : : "memory");
    return dst;
}

void* memmove(void* dst, const void* src, size_t count) {
    u8* d = (u8*)dst;
    const u8* s = (const u8*)src;
    if (d <= s || d >= s + count) {
        void* dd = dst;
        const void* ss = src;
        __asm__ volatile("rep movsb" : "+D"(dd), "+S"(ss), "+c"(count) : : "memory");
    } else {
        for (size_t i = count; i > 0; --i) d[i - 1] = s[i - 1];
    }
    return dst;
}

int memcmp(const void* a, const void* b, size_t count) {
    const u8* x = (const u8*)a;
    const u8* y = (const u8*)b;
    for (size_t i = 0; i < count; ++i)
        if (x[i] != y[i]) return (int)x[i] - (int)y[i];
    return 0;
}

int _purecall() { return 0; }

// Последовательное касание страниц стека (стандартный __chkstk x64).
void __chkstk() __attribute__((naked));
void __chkstk() {
    __asm__(
        "push %rcx\n\tpush %rax\n\tlea 24(%rsp), %rcx\n\t"
        "cmp $4096, %rax\n\tjb 2f\n\t"
        "1: sub $4096, %rcx\n\ttestb $0, (%rcx)\n\t"
        "sub $4096, %rax\n\tcmp $4096, %rax\n\tjae 1b\n\t"
        "2: sub %rax, %rcx\n\ttestb $0, (%rcx)\n\t"
        "pop %rax\n\tpop %rcx\n\tret");
}

}  // extern "C"

void* operator new(size_t n) { return nek::xalloc(n); }
void* operator new[](size_t n) { return nek::xalloc(n); }
void operator delete(void* p) noexcept { nek::xfree(p); }
void operator delete(void* p, size_t) noexcept { nek::xfree(p); }
void operator delete[](void* p) noexcept { nek::xfree(p); }
void operator delete[](void* p, size_t) noexcept { nek::xfree(p); }

namespace nek {

void* xalloc(size_t n) { return plat_alloc(n ? n : 1); }
void* xrealloc(void* p, size_t n) { return plat_realloc(p, n ? n : 1); }
void xfree(void* p) { if (p) plat_free(p); }

void wipe(void* p, size_t n) {
    volatile u8* v = (volatile u8*)p;
    while (n--) *v++ = 0;
}

size_t cstrlen(const char* s) {
    size_t n = 0;
    if (s) while (s[n]) ++n;
    return n;
}

bool mem_eq(const void* a, const void* b, size_t n) {
    const u8* x = (const u8*)a;
    const u8* y = (const u8*)b;
    for (size_t i = 0; i < n; ++i)
        if (x[i] != y[i]) return false;
    return true;
}

bool ct_eq(const void* a, const void* b, size_t n) {
    const volatile u8* x = (const volatile u8*)a;
    const volatile u8* y = (const volatile u8*)b;
    u8 acc = 0;
    for (size_t i = 0; i < n; ++i) acc |= (u8)(x[i] ^ y[i]);
    return acc == 0;
}

// ---- Bytes ---------------------------------------------------------------

void Bytes::reset() {
    if (p) {
        wipe(p, cap + 1);
        xfree(p);
    }
    p = 0;
    n = cap = 0;
}

bool Bytes::reserve(size_t total) {
    if (total <= cap && p) return true;
    size_t nc = cap ? cap * 2 : 32;
    if (nc < total) nc = total;
    u8* np = (u8*)xalloc(nc + 1);
    if (!np) return false;
    if (p) {
        memcpy(np, p, n);
        wipe(p, cap + 1);
        xfree(p);
    }
    np[n] = 0;
    p = np;
    cap = nc;
    return true;
}

bool Bytes::resize(size_t newlen) {
    if (!reserve(newlen)) return false;
    if (newlen > n) memset(p + n, 0, newlen - n);
    n = newlen;
    p[n] = 0;
    return true;
}

bool Bytes::append(const void* src, size_t len) {
    if (len == 0) return reserve(n);
    if (!reserve(n + len)) return false;
    memcpy(p + n, src, len);
    n += len;
    p[n] = 0;
    return true;
}

}  // namespace nek
