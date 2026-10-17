// NEKalkan — слой над ОС: Windows x64 без windows.h.
#include "plat.h"
#include "codec.h"

typedef void* HANDLE;
typedef unsigned long DWORD;
typedef int BOOL;
typedef unsigned short WCHAR;

extern "C" {
__declspec(dllimport) HANDLE __stdcall GetProcessHeap();
__declspec(dllimport) void* __stdcall HeapAlloc(HANDLE, DWORD, size_t);
__declspec(dllimport) void* __stdcall HeapReAlloc(HANDLE, DWORD, void*, size_t);
__declspec(dllimport) BOOL __stdcall HeapFree(HANDLE, DWORD, void*);
__declspec(dllimport) HANDLE __stdcall CreateFileW(const WCHAR*, DWORD, DWORD, void*, DWORD, DWORD, HANDLE);
__declspec(dllimport) BOOL __stdcall ReadFile(HANDLE, void*, DWORD, DWORD*, void*);
__declspec(dllimport) BOOL __stdcall WriteFile(HANDLE, const void*, DWORD, DWORD*, void*);
__declspec(dllimport) BOOL __stdcall GetFileSizeEx(HANDLE, long long*);
__declspec(dllimport) BOOL __stdcall CloseHandle(HANDLE);
__declspec(dllimport) DWORD __stdcall GetFileAttributesW(const WCHAR*);
__declspec(dllimport) void __stdcall GetSystemTimeAsFileTime(unsigned long long*);
__declspec(dllimport) void __stdcall OutputDebugStringA(const char*);
__declspec(dllimport) int __stdcall MultiByteToWideChar(unsigned, DWORD, const char*, int, WCHAR*, int);
__declspec(dllimport) int __stdcall WideCharToMultiByte(unsigned, DWORD, const WCHAR*, int, char*, int, const char*, BOOL*);
__declspec(dllimport) BOOL __stdcall FileTimeToSystemTime(const unsigned long long*, unsigned short*);
__declspec(dllimport) BOOL __stdcall SystemTimeToTzSpecificLocalTime(const void*, const unsigned short*, unsigned short*);
__declspec(dllimport) unsigned char __stdcall SystemFunction036(void*, unsigned long);  // RtlGenRandom (advapi32)
__declspec(dllimport) void* __stdcall VirtualAlloc(void*, size_t, DWORD, DWORD);
__declspec(dllimport) BOOL __stdcall VirtualProtect(void*, size_t, DWORD, DWORD*);
__declspec(dllimport) BOOL __stdcall VirtualFree(void*, size_t, DWORD);
}

namespace nek {

#ifdef NEK_GUARD_HEAP
// Отладочная куча для тестов (tools/build.ps1 -Guard): каждый блок — отдельные страницы, сразу за концом блока стоит
// недоступная страница (выход за границу вверх — исключение доступа), освобождённая память отключается (use-after-free — исключение).
struct GuardHdr { void* base; size_t n; };
static long g_live = 0;
static const size_t kPage = 4096;

void* plat_alloc(size_t n) {
    size_t body = (n + sizeof(GuardHdr) + 7) & ~(size_t)7;
    size_t pages = (body + kPage - 1) / kPage * kPage;
    char* base = (char*)VirtualAlloc(0, pages + kPage, 0x3000 /*MEM_COMMIT|MEM_RESERVE*/, 0x04 /*PAGE_READWRITE*/);
    if (!base) return 0;
    DWORD old;
    VirtualProtect(base + pages, kPage, 0x01 /*PAGE_NOACCESS*/, &old);
    size_t user_off = pages - ((n + 7) & ~(size_t)7);          // блок заканчивается у границы страницы (с точностью до выравнивания 8)
    char* user = base + user_off;
    GuardHdr* h = (GuardHdr*)(user - sizeof(GuardHdr));
    h->base = base;
    h->n = n;
    __atomic_fetch_add(&g_live, 1, __ATOMIC_RELAXED);
    return user;
}
void plat_free(void* p) {
    if (!p) return;
    GuardHdr* h = (GuardHdr*)((char*)p - sizeof(GuardHdr));
    __atomic_fetch_sub(&g_live, 1, __ATOMIC_RELAXED);
    VirtualFree(h->base, 0, 0x4000 /*MEM_DECOMMIT*/);        // адреса не возвращаем: доступ после освобождения — исключение
}
long plat_live_allocs() { return g_live; }
void* plat_realloc(void* p, size_t n) {
    void* q = plat_alloc(n);
    if (!q) return 0;
    if (p) {
        GuardHdr* h = (GuardHdr*)((char*)p - sizeof(GuardHdr));
        memcpy(q, p, h->n < n ? h->n : n);
        plat_free(p);
    }
    return q;
}
#else
long plat_live_allocs() { return -1; }
void* plat_alloc(size_t n) { return HeapAlloc(GetProcessHeap(), 0, n); }
void* plat_realloc(void* p, size_t n) {
    return p ? HeapReAlloc(GetProcessHeap(), 0, p, n) : HeapAlloc(GetProcessHeap(), 0, n);
}
void plat_free(void* p) { HeapFree(GetProcessHeap(), 0, p); }
#endif

bool plat_random(void* buf, size_t n) {
    u8* p = (u8*)buf;
    while (n) {
        unsigned long chunk = n > 0x10000 ? 0x10000 : (unsigned long)n;
        if (!SystemFunction036(p, chunk)) return false;
        p += chunk;
        n -= chunk;
    }
    return true;
}

i64 plat_unix_time() {
    unsigned long long ft = 0;
    GetSystemTimeAsFileTime(&ft);                     // 100-нс интервалы от 1601-01-01
    return (i64)(ft / 10000000ULL) - 11644473600LL;
}

i64 plat_local_offset(i64 unix_utc) {
    unsigned long long ft = (unsigned long long)(unix_utc + 11644473600LL) * 10000000ULL;
    unsigned short utc[8], loc[8];
    if (!FileTimeToSystemTime(&ft, utc) || !SystemTimeToTzSpecificLocalTime(0, utc, loc)) return 0;
    DateTime d = {loc[0], loc[1], loc[3], loc[4], loc[5], loc[6]};
    return to_unix(d) - unix_utc;
}

// UTF-8 → UTF-16 (с завершающим нулём). Возвращает 0 при ошибке; освобождать xfree.
// Длинные абсолютные пути (≥ 248 символов) получают префикс \?\ — иначе Windows без манифеста отвергает путь длиннее MAX_PATH.
static WCHAR* utf8_to_wide(const char* s) {
    const WCHAR BS = 0x5C;
    int len = MultiByteToWideChar(65001, 0, s, -1, 0, 0);
    if (len <= 0) return 0;
    size_t extra = len >= 248 ? 8 : 0;
    WCHAR* w = (WCHAR*)xalloc(((size_t)len + extra) * sizeof(WCHAR));
    if (!w) return 0;
    if (MultiByteToWideChar(65001, 0, s, -1, w + extra, len) <= 0) { xfree(w); return 0; }
    if (extra) {
        WCHAR* body = w + extra;
        for (int i = 0; i < len; ++i) if (body[i] == '/') body[i] = BS;
        bool drive = len > 3 && body[1] == ':' && body[2] == BS && ((body[0] | 0x20) >= 'a' && (body[0] | 0x20) <= 'z');
        bool unc = len > 3 && body[0] == BS && body[1] == BS && body[2] != '?' && body[2] != '.';
        if (drive) {                                   // диск: X:, префикс "BS BS ? BS"
            w[0] = BS; w[1] = BS; w[2] = '?'; w[3] = BS;
            memmove(w + 4, body, (size_t)len * sizeof(WCHAR));
        } else if (unc) {                              // сетевой путь: префикс "BS BS ? BS UNC BS"
            w[0] = BS; w[1] = BS; w[2] = '?'; w[3] = BS; w[4] = 'U'; w[5] = 'N'; w[6] = 'C'; w[7] = BS;
            memmove(w + 8, body + 2, (size_t)(len - 2) * sizeof(WCHAR));
        } else {
            memmove(w, body, (size_t)len * sizeof(WCHAR));
        }
    }
    return w;
}

bool plat_read_file(const char* path, Bytes& out) {
    WCHAR* w = utf8_to_wide(path);
    if (!w) return false;
    HANDLE h = CreateFileW(w, 0x80000000u /*GENERIC_READ*/, 1 /*SHARE_READ*/, 0, 3 /*OPEN_EXISTING*/, 0x80, 0);
    xfree(w);
    if (h == (HANDLE)(long long)-1) return false;
    long long size = 0;
    bool ok = GetFileSizeEx(h, &size) && size >= 0 && size < 0x7FFFFFF0LL;
    out.clear();
    if (ok) ok = out.reserve((size_t)size);
    size_t done = 0;
    while (ok && done < (size_t)size) {
        DWORD got = 0;
        DWORD want = (size_t)size - done > 0x100000 ? 0x100000 : (DWORD)((size_t)size - done);
        if (!ReadFile(h, out.p + done, want, &got, 0) || got == 0) { ok = false; break; }
        done += got;
    }
    if (ok) { out.n = (size_t)size; out.p[out.n] = 0; }
    CloseHandle(h);
    return ok;
}

bool plat_write_file(const char* path, Span data) {
    WCHAR* w = utf8_to_wide(path);
    if (!w) return false;
    HANDLE h = CreateFileW(w, 0x40000000u /*GENERIC_WRITE*/, 0, 0, 2 /*CREATE_ALWAYS*/, 0x80, 0);
    xfree(w);
    if (h == (HANDLE)(long long)-1) return false;
    bool ok = true;
    size_t done = 0;
    while (ok && done < data.n) {
        DWORD put = 0;
        DWORD want = data.n - done > 0x100000 ? 0x100000 : (DWORD)(data.n - done);
        if (!WriteFile(h, data.p + done, want, &put, 0) || put == 0) { ok = false; break; }
        done += put;
    }
    CloseHandle(h);
    return ok;
}

bool plat_file_exists(const char* path) {
    WCHAR* w = utf8_to_wide(path);
    if (!w) return false;
    DWORD a = GetFileAttributesW(w);
    xfree(w);
    return a != 0xFFFFFFFFu && !(a & 0x10);
}

void plat_debug(const char* msg) { OutputDebugStringA(msg); }

bool plat_acp_from_wide(const u16* w, size_t n, Bytes& out) {
    out.clear();
    if (!n) return true;
    if (n > 0x3FFFFFFF) return false;
    BOOL used_default = 0;
    int len = WideCharToMultiByte(0 /*CP_ACP*/, 0, (const WCHAR*)w, (int)n, 0, 0, 0, &used_default);
    if (len <= 0 || used_default || !out.resize((size_t)len)) return false;
    used_default = 0;
    if (WideCharToMultiByte(0, 0, (const WCHAR*)w, (int)n, (char*)out.p, len, 0, &used_default) != len || used_default) { out.clear(); return false; }
    return true;
}

bool plat_acp_to_wide(Span in, Vec<u16>& out) {
    if (!in.n) return true;
    if (in.n > 0x3FFFFFFF) return false;
    int len = MultiByteToWideChar(0 /*CP_ACP*/, 0, (const char*)in.p, (int)in.n, 0, 0);
    if (len <= 0) return false;
    size_t base = out.n;
    if (!out.reserve(base + (size_t)len)) return false;
    if (MultiByteToWideChar(0, 0, (const char*)in.p, (int)in.n, (WCHAR*)(out.d + base), len) != len) return false;
    out.n = base + (size_t)len;
    return true;
}

}  // namespace nek

extern "C" int __stdcall DllMain(void*, unsigned long, void*) { return 1; }
