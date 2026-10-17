// NEKalkan — минимальная среда выполнения без CRT и без исключений.
//
// Сборка: clang++ -ffreestanding -fno-exceptions -fno-rtti -nostdlib (см. tools/build.ps1).
// Здесь только типы, память и два контейнера (Bytes, Vec). Никакого std::.
#pragma once

#include <stddef.h>
#include <stdint.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int32_t i32;
typedef int64_t i64;

inline void* operator new(size_t, void* p) noexcept { return p; }

extern "C" {
void* memcpy(void* dst, const void* src, size_t n);
void* memmove(void* dst, const void* src, size_t n);
void* memset(void* dst, int v, size_t n);
int memcmp(const void* a, const void* b, size_t n);
}

namespace nek {

// ---- память ---------------------------------------------------------------

void* xalloc(size_t n);                 // 0 при нехватке памяти; память НЕ обнуляется
void* xrealloc(void* p, size_t n);
void xfree(void* p);
void wipe(void* p, size_t n);           // затирание, которое не вырезается оптимизатором

// ---- простые строковые/байтовые утилиты -------------------------------------

size_t cstrlen(const char* s);
bool mem_eq(const void* a, const void* b, size_t n);
bool ct_eq(const void* a, const void* b, size_t n);  // сравнение за постоянное время

// Неизменяемое представление байтов (не владеет памятью).
struct Span {
    const u8* p;
    size_t n;
    Span() : p(0), n(0) {}
    Span(const u8* pp, size_t nn) : p(pp), n(nn) {}
    Span(const char* s) : p((const u8*)s), n(cstrlen(s)) {}
    Span(const char* s, size_t nn) : p((const u8*)s), n(nn) {}
    Span sub(size_t off, size_t len) const { return Span(p + off, len); }
    bool eq(Span o) const { return n == o.n && mem_eq(p, o.p, n); }
};

// ---- Bytes: владеющий растущий буфер ---------------------------------------
//
// Все операции, которые могут не получить память, возвращают false.
// Буфер всегда имеет один лишний нулевой байт за p[n] (удобно как C-строка).
// При разрушении память затирается (в буферах бывают пароли и ключи).
class Bytes {
public:
    u8* p;
    size_t n;
    size_t cap;

    Bytes() : p(0), n(0), cap(0) {}
    ~Bytes() { reset(); }
    Bytes(Bytes&& o) : p(o.p), n(o.n), cap(o.cap) { o.p = 0; o.n = o.cap = 0; }
    Bytes& operator=(Bytes&& o) {
        if (this != &o) { reset(); p = o.p; n = o.n; cap = o.cap; o.p = 0; o.n = o.cap = 0; }
        return *this;
    }
    Bytes(const Bytes&) = delete;
    Bytes& operator=(const Bytes&) = delete;

    void reset();                         // освободить и затереть
    void clear() { n = 0; if (p) p[0] = 0; }
    bool reserve(size_t total);
    bool resize(size_t newlen);           // новые байты обнуляются
    bool append(const void* src, size_t len);
    bool append(Span s) { return append(s.p, s.n); }
    bool append_str(const char* s) { return append(s, cstrlen(s)); }
    bool push(u8 b) { return append(&b, 1); }
    bool assign(Span s) { clear(); return append(s); }
    bool copy_from(const Bytes& o) { clear(); return append(o.p, o.n); }

    Span span() const { return Span(p, n); }
    const char* cstr() const { return p ? (const char*)p : ""; }
    u8& operator[](size_t i) { return p[i]; }
    const u8& operator[](size_t i) const { return p[i]; }
    bool empty() const { return n == 0; }
};

// ---- Vec<T>: растущий массив для «тривиально перемещаемых» T ---------------
// T перемещается memcpy; деструкторы элементов не вызываются автоматически —
// владельцы сами освобождают то, что лежит в элементах (см. free_each).
template <class T>
class Vec {
public:
    T* d;
    size_t n;
    size_t cap;
    Vec() : d(0), n(0), cap(0) {}
    ~Vec() { xfree(d); }
    Vec(const Vec&) = delete;
    Vec& operator=(const Vec&) = delete;
    bool reserve(size_t total) {
        if (total <= cap) return true;
        size_t nc = cap ? cap * 2 : 4;
        if (nc < total) nc = total;
        T* nd = (T*)xrealloc(d, nc * sizeof(T));
        if (!nd) return false;
        d = nd; cap = nc; return true;
    }
    bool push(const T& v) {
        if (!reserve(n + 1)) return false;
        d[n++] = v; return true;
    }
    T& operator[](size_t i) { return d[i]; }
    const T& operator[](size_t i) const { return d[i]; }
    void clear() { n = 0; }
};

// ---- коды результата в стиле Kalkan (KCR_*) --------------------------------
// Значения совпадают с KalkanCrypt SDK, чтобы 1С-код, написанный под Калкан, не менялся.
enum : u32 {
    KCR_BASE = 0x08F00000,
    KCR_OK = 0,
    KCR_INIT_ERROR = KCR_BASE + 0x01,
    KCR_ERROR_READ_PKCS12 = KCR_BASE + 0x02,
    KCR_ERROR_OPEN_PKCS12 = KCR_BASE + 0x03,
    KCR_INVALID_PROPID = KCR_BASE + 0x04,
    KCR_BUFFER_TOO_SMALL = KCR_BASE + 0x05,
    KCR_CERT_PARSE_ERROR = KCR_BASE + 0x06,
    KCR_INVALID_FLAG = KCR_BASE + 0x07,
    KCR_OPENFILEERR = KCR_BASE + 0x08,
    KCR_INVALIDPASSWORD = KCR_BASE + 0x09,
    KCR_CERTWRONGDATE = KCR_BASE + 0x0a,
    KCR_CERTEXPIRED = KCR_BASE + 0x0b,
    KCR_ISNOTCACERT = KCR_BASE + 0x0c,
    KCR_MEMORY_ERROR = KCR_BASE + 0x0d,
    KCR_CHECKCHAINERROR = KCR_BASE + 0x0e,
    KCR_CACERTKEYUSAGEERROR = KCR_BASE + 0x0f,
    KCR_VALIDTYPEERROR = KCR_BASE + 0x10,
    KCR_BADCRLFORMAT = KCR_BASE + 0x11,
    KCR_LOADCRLERROR = KCR_BASE + 0x12,
    KCR_LOADCRLSERROR = KCR_BASE + 0x13,
    KCR_UNKNOWN_ALG = KCR_BASE + 0x15,
    KCR_KEY_NOT_FOUND = KCR_BASE + 0x16,
    KCR_SIGN_INIT_ERROR = KCR_BASE + 0x17,
    KCR_SIGN_ERROR = KCR_BASE + 0x18,
    KCR_ENCODE_ERROR = KCR_BASE + 0x19,
    KCR_INVALID_FLAGS = KCR_BASE + 0x1a,
    KCR_CERTNOTFOUND = KCR_BASE + 0x1b,
    KCR_VERIFYSIGNERROR = KCR_BASE + 0x1c,
    KCR_BASE64_DECODE_ERROR = KCR_BASE + 0x1d,
    KCR_UNKNOWN_CMS_FORMAT = KCR_BASE + 0x1e,
    KCR_GETHASHERROR = KCR_BASE + 0x1f,
    KCR_CA_CERT_NOT_FOUND = KCR_BASE + 0x20,
    KCR_XMLSECINIT_ERROR = KCR_BASE + 0x21,
    KCR_LOADTRUSTEDCERTSERR = KCR_BASE + 0x22,
    KCR_SIGN_INVALID = KCR_BASE + 0x23,
    KCR_NOSIGNFOUND = KCR_BASE + 0x24,
    KCR_DECODE_ERROR = KCR_BASE + 0x25,
    KCR_XMLPARSEERROR = KCR_BASE + 0x26,
    KCR_XMLADDIDERROR = KCR_BASE + 0x27,
    KCR_XMLINTERNALERROR = KCR_BASE + 0x28,
    KCR_XMLSETSIGNERROR = KCR_BASE + 0x29,
    KCR_OPENSSLERROR = KCR_BASE + 0x2a,
    KCR_VERIFY_INIT_ERROR = KCR_BASE + 0x3c,
    KCR_VERIFY_ERROR = KCR_BASE + 0x3d,
    KCR_HASH_ERROR = KCR_BASE + 0x3e,
    KCR_SIGNHASH_ERROR = KCR_BASE + 0x3f,
    KCR_CACERTNOTFOUND = KCR_BASE + 0x40,
    KCR_LIBRARYNOTINITIALIZED = KCR_BASE + 0x101,
    KCR_PARAM_ERROR = KCR_BASE + 0x300,
    KCR_NOTOKENFOUND = KCR_BASE + 0x2c,
    KCR_OCSP_ADDCERTERR = KCR_BASE + 0x2d,
    KCR_OCSP_PARSEURLERR = KCR_BASE + 0x2e,
    KCR_OCSP_ADDHOSTERR = KCR_BASE + 0x2f,
    KCR_OCSP_REQERR = KCR_BASE + 0x30,
    KCR_OCSP_CONNECTIONERR = KCR_BASE + 0x31,
    KCR_VERIFY_NODATA = KCR_BASE + 0x32,
    KCR_IDATTR_NOTFOUND = KCR_BASE + 0x33,
    KCR_IDRANGE = KCR_BASE + 0x34,
    KCR_READERNOTFOUND = KCR_BASE + 0x37,
    KCR_GETCERTPROPERR = KCR_BASE + 0x38,
    KCR_SIGNFORMMAT = KCR_BASE + 0x39,
    KCR_INDATAFORMAT = KCR_BASE + 0x3a,
    KCR_OUTDATAFORMAT = KCR_BASE + 0x3b,
    KCR_CERTTIMEINVALID = KCR_BASE + 0x42,
    KCR_CONVERTERROR = KCR_BASE + 0x43,
    KCR_HTTPERROR = KCR_BASE + 0x47,
    KCR_NOTSATOKEN = KCR_BASE + 0x4a,
    KCR_INVALID_DIGEST_LEN = KCR_BASE + 0x4b,
    KCR_GENRANDERROR = KCR_BASE + 0x4c,
    KCR_SOAPNSERROR = KCR_BASE + 0x4d,
    KCR_GETPUBKEY = KCR_BASE + 0x4e,
    KCR_GETCERTINFO = KCR_BASE + 0x4f,
    KCR_FILEREADERROR = KCR_BASE + 0x50,
    KCR_CHECKERROR = KCR_BASE + 0x51,
    KCR_ZIPEXTRACTERR = KCR_BASE + 0x52,
    KCR_NOMANIFESTFILE = KCR_BASE + 0x53,
    KCR_CERT_STATUS_OK = KCR_BASE + 0x400,
    KCR_CERT_STATUS_REVOKED = KCR_BASE + 0x401,
    KCR_CERT_STATUS_UNKNOWN = KCR_BASE + 0x402,
};

}  // namespace nek
