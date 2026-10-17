// NEKalkan — внешняя компонента Native API 1С:Предприятия (x64 Windows).
//
// Вся прикладная логика — в api_call (api1c_dispatch.cpp); здесь только мост к платформе: интерфейсы IComponentBase,
// преобразование tVariant <-> байты/строки, память IMemoryManager, регистрация ошибок через AddError.
// Экспортируемые функции: GetClassNames, GetClassObject, DestroyObject, SetPlatformCapabilities, GetAttachType.
#include "api1c.h"
#include "codec.h"
#include "plat.h"
#include "native_types.h"

namespace nek {
namespace {

// Имя класса обязано совпадать с именем расширения (RegisterExtensionAs): платформа 8.3.27 регистрирует тип только по нему,
// второе имя через «|» не создаётся (проверено в реальной 1С).
const WCHAR_T kClassNames[] = u"NEKalkan";
const WCHAR_T kExtensionName[] = u"NEKalkan";

const u32 WRAP_BASE_ = 0x0A510000;
const u32 WRAP_INVALID_PARAMETER_ = WRAP_BASE_ + 5;
const u32 WRAP_MEMORY_ERROR_ = WRAP_BASE_ + 6;

// ---- tVariant ---------------------------------------------------------------------------------------------------

void var_init(tVariant* v) {
    memset(v, 0, sizeof(tVariant));
    v->vt = VTYPE_EMPTY;
}

// Параметр, переданный по ссылке (BYREF), — это указатель на другой tVariant.
tVariant* unref(tVariant* v) {
    for (int depth = 0; v && depth < 16; ++depth) {
        if (!(v->vt & VTYPE_BYREF)) return v;
        if ((v->vt & VTYPE_TYPEMASK) != VTYPE_VARIANT) return 0;
        v = v->pvarVal;
    }
    return 0;
}

// Строчная форма для сравнения имён: латиница и кириллица (включая Ё).
u16 fold(u16 c) {
    if (c >= 'A' && c <= 'Z') return (u16)(c + 32);
    if (c >= 0x0410 && c <= 0x042F) return (u16)(c + 32);
    if (c >= 0x0400 && c <= 0x040F) return (u16)(c + 80);
    return c;
}

bool names_equal(const u16* a, size_t an, const Vec<u16>& b) {
    if (an != b.n) return false;
    for (size_t i = 0; i < an; ++i) if (fold(a[i]) != fold(b.d[i])) return false;
    return true;
}

size_t wlen(const WCHAR_T* s) {
    size_t n = 0;
    while (s && s[n]) ++n;
    return n;
}

// ---- хост: параметры и результаты одного вызова -------------------------------------------------------------------

class NativeHost : public ApiHost {
public:
    NativeHost(IMemoryManager* mem, int& enc, tVariant* params, long n, tVariant* ret)
        : failed(false), mem_(mem), enc_(enc), params_(params), n_(n), ret_(ret) {}

    bool failed;      // не удалось выделить память под результат

    int arg_count() override { return (int)n_; }

    bool arg_int(int i, i64& v) override {
        const tVariant* a = arg(i);
        if (!a) return false;
        switch (a->vt & VTYPE_TYPEMASK) {
            case VTYPE_I1: v = a->i8Val; return true;
            case VTYPE_UI1: v = a->ui8Val; return true;
            case VTYPE_I2: v = a->shortVal; return true;
            case VTYPE_UI2: v = a->ushortVal; return true;
            case VTYPE_I4: case VTYPE_INT: v = a->lVal; return true;
            case VTYPE_UI4: case VTYPE_UINT: v = (i64)a->ulVal; return true;
            case VTYPE_I8: v = a->llVal; return true;
            case VTYPE_UI8: v = (i64)a->ullVal; return true;
            case VTYPE_BOOL: v = a->bVal ? 1 : 0; return true;
            case VTYPE_R8: return from_double(a->dblVal, v);
            case VTYPE_R4: return from_double((double)a->fltVal, v);
            default: return false;
        }
    }

    // Имя/путь/пароль — всегда UTF-8 для движка.
    bool arg_name(int i, Bytes& out) override {
        const tVariant* a = arg(i);
        if (!a) return false;
        switch (a->vt & VTYPE_TYPEMASK) {
            case VTYPE_EMPTY: case VTYPE_NULL: return true;
            case VTYPE_PWSTR:
                if (!wstr_ok(a)) return false;
                return utf16_to_utf8((const u16*)a->pwstrVal, a->wstrLen, out);
            case VTYPE_PSTR: case VTYPE_BLOB:
                if (!str_ok(a)) return false;
                return bytes_to_utf8(Span((const u8*)a->pstrVal, a->strLen), out);
            default: return false;
        }
    }

    // Данные для хэша/подписи: строка 1С — в кодировке обмена, BLOB — как есть.
    bool arg_data(int i, Bytes& out) override {
        const tVariant* a = arg(i);
        if (!a) return false;
        switch (a->vt & VTYPE_TYPEMASK) {
            case VTYPE_EMPTY: case VTYPE_NULL: return true;
            case VTYPE_PWSTR:
                if (!wstr_ok(a)) return false;
                return text_to_bytes((const u16*)a->pwstrVal, a->wstrLen, out);
            case VTYPE_PSTR: case VTYPE_BLOB:
                if (!str_ok(a)) return false;
                return out.append((const u8*)a->pstrVal, a->strLen);
            default: return false;
        }
    }

    bool arg_xml(int i, Bytes& out, bool& was_text) override {
        const tVariant* a = arg(i);
        was_text = true;
        if (!a) return false;
        switch (a->vt & VTYPE_TYPEMASK) {
            case VTYPE_EMPTY: case VTYPE_NULL: return true;
            case VTYPE_PWSTR:
                if (!wstr_ok(a)) return false;
                return utf16_to_utf8((const u16*)a->pwstrVal, a->wstrLen, out);
            case VTYPE_PSTR: case VTYPE_BLOB:
                if (!str_ok(a)) return false;
                was_text = false;
                return out.append((const u8*)a->pstrVal, a->strLen);
            default: return false;
        }
    }

    bool put_int(int i, i64 v) override {
        tVariant* d = slot(i);
        if (!d) return fail();
        reuse(d);
        var_init(d);
        d->lVal = (int)v;               // коды KCR_* — 32-битные, как у KalkanCryptNative1C
        d->vt = VTYPE_I4;
        return true;
    }

    bool put_text(int i, Span utf8) override {
        Vec<u16> w;
        if (!utf8_to_utf16_lossy(utf8, w)) return fail();
        return set_wstr(i, w.d, w.n);
    }

    bool put_data(int i, Span b) override {
        Vec<u16> w;
        bool text;
        if (enc_ == ENC_UTF8) text = utf8_valid(b) && utf8_to_utf16(b, w);
        else if (enc_ == ENC_CP1251) { Bytes u; text = cp1251_to_utf8(b, u) && utf8_to_utf16(u.span(), w); }
        else text = plat_acp_to_wide(b, w);
        return text ? set_wstr(i, w.d, w.n) : put_blob(i, b);
    }

    bool put_blob(int i, Span b) override {
        tVariant* d = slot(i);
        if (!d || !mem_ || b.n > 0x7FFFFFE0u) return fail();
        char* p = 0;
        if (!mem_->AllocMemory((void**)&p, (unsigned long)(b.n ? b.n : 1)) || !p) return fail();
        if (b.n) memcpy(p, b.p, b.n); else p[0] = 0;
        reuse(d);
        var_init(d);
        d->pstrVal = p;
        d->strLen = (unsigned int)b.n;
        d->vt = VTYPE_BLOB;
        return true;
    }

    bool set_encoding(Span name) override { return api_parse_encoding(name, enc_); }
    const char* encoding_name() override { return api_encoding_name(enc_); }

    // Строка UTF-16 в памяти платформы.
    bool set_wstr(int i, const u16* w, size_t n) {
        tVariant* d = slot(i);
        if (!d) return fail();
        WCHAR_T* p = alloc_wstr(mem_, w, n);
        if (!p) return fail();
        reuse(d);
        var_init(d);
        d->pwstrVal = p;
        d->wstrLen = (unsigned int)n;
        d->vt = VTYPE_PWSTR;
        return true;
    }

    static WCHAR_T* alloc_wstr(IMemoryManager* mem, const u16* w, size_t n) {
        if (!mem || n > 0x3FFFFFFFu) return 0;
        WCHAR_T* p = 0;
        if (!mem->AllocMemory((void**)&p, (unsigned long)((n + 1) * sizeof(WCHAR_T))) || !p) return 0;
        if (n) memcpy(p, w, n * sizeof(WCHAR_T));
        p[n] = 0;
        return p;
    }

private:
    IMemoryManager* mem_;
    int& enc_;
    tVariant* params_;
    long n_;
    tVariant* ret_;

    bool fail() { failed = true; return false; }

    // Слот могут занимать два выходных параметра (одна и та же переменная 1С передана дважды): буфер, выделенный нами раньше
    // в этом же вызове, освобождаем при перезаписи. Чужие (пришедшие от платформы) значения не трогаем.
    tVariant* written_[16];
    int nwritten_ = 0;
    void reuse(tVariant* d) {
        for (int k = 0; k < nwritten_; ++k) {
            if (written_[k] != d) continue;
            if (mem_) {
                if (d->vt == VTYPE_PWSTR && d->pwstrVal) mem_->FreeMemory((void**)&d->pwstrVal);
                else if (d->vt == VTYPE_BLOB && d->pstrVal) mem_->FreeMemory((void**)&d->pstrVal);
            }
            return;
        }
        if (nwritten_ < 16) written_[nwritten_++] = d;
    }

    const tVariant* arg(int i) {
        if (i < 0 || i >= n_ || !params_) return 0;
        return unref(&params_[i]);
    }
    tVariant* slot(int i) {
        if (i < 0) return ret_;
        if (i >= n_ || !params_) return 0;
        return unref(&params_[i]);
    }

    static bool from_double(double d, i64& v) {
        if (!(d >= -9.0e15 && d <= 9.0e15)) return false;
        i64 x = (i64)d;
        if ((double)x != d) return false;
        v = x;
        return true;
    }
    static bool wstr_ok(const tVariant* a) { return a->wstrLen <= 0x3FFFFFFFu && (a->wstrLen == 0 || a->pwstrVal); }
    static bool str_ok(const tVariant* a) { return a->strLen <= 0x7FFFFFE0u && (a->strLen == 0 || a->pstrVal); }

    // Строка 1С -> байты в кодировке обмена. false — символ не представим (подпись над искажёнными данными недопустима).
    bool text_to_bytes(const u16* w, size_t n, Bytes& out) {
        if (enc_ == ENC_UTF8) return utf16_to_utf8(w, n, out);
        if (enc_ == ENC_CP1251) {
            Bytes u;
            return utf16_to_utf8(w, n, u) && utf8_to_cp1251(u.span(), out);
        }
        return plat_acp_from_wide(w, n, out);
    }

    // Байты в кодировке обмена -> UTF-8.
    bool bytes_to_utf8(Span b, Bytes& out) {
        if (enc_ == ENC_UTF8) return out.append(b);
        if (enc_ == ENC_CP1251) return cp1251_to_utf8(b, out);
        Vec<u16> w;
        return plat_acp_to_wide(b, w) && utf16_to_utf8(w.d, w.n, out);
    }
};

// ---- компонента --------------------------------------------------------------------------------------------------

class Component : public IComponentBase {
public:
    Component() : platform_(0), mem_(0), enc_(ENC_UTF8) {}
    ~Component() override {}

    bool Init(void* disp) override { platform_ = (IAddInDefBase*)disp; return true; }
    bool setMemManager(void* mem) override { mem_ = (IMemoryManager*)mem; return mem_ != 0; }
    long GetInfo() override { return 2000; }
    void Done() override {
        st_.kc.Finalize();              // затереть ключ и сертификаты
        platform_ = 0;
        mem_ = 0;                       // после Done() платформа вправе освободить менеджер памяти
    }

    bool RegisterExtensionAs(WCHAR_T** name) override {
        if (!name) return false;
        *name = NativeHost::alloc_wstr(mem_, (const u16*)kExtensionName, wlen(kExtensionName));
        return *name != 0;
    }

    // ---- свойства: константы KC_*/KCR_*/WRAP_* (только чтение)
    long GetNProps() override { return API_CONST_COUNT; }
    long FindProp(const WCHAR_T* name) override {
        if (!name) return -1;
        size_t n = wlen(name);
        for (int i = 0; i < API_CONST_COUNT; ++i) {
            const char* cn; i32 cv;
            api_const(i, &cn, &cv);
            Vec<u16> w;
            if (utf8_to_utf16(Span(cn), w) && names_equal((const u16*)name, n, w)) return i;
        }
        return -1;
    }
    const WCHAR_T* GetPropName(long num, long) override {
        const char* cn; i32 cv;
        if (!api_const((int)num, &cn, &cv)) return 0;
        return alloc_ascii(cn);
    }
    bool GetPropVal(const long num, tVariant* v) override {
        const char* cn; i32 cv;
        if (!v || !api_const((int)num, &cn, &cv)) return false;
        var_init(v);
        v->lVal = cv;
        v->vt = VTYPE_I4;
        return true;
    }
    bool SetPropVal(const long, tVariant*) override { return false; }
    bool IsPropReadable(const long num) override { return num >= 0 && num < API_CONST_COUNT; }
    bool IsPropWritable(const long) override { return false; }

    // ---- методы
    long GetNMethods() override { return API_METHOD_COUNT; }
    long FindMethod(const WCHAR_T* name) override {
        if (!name) return -1;
        size_t n = wlen(name);
        for (int i = 0; i < API_METHOD_COUNT; ++i) {
            Vec<u16> en, ru;
            if (utf8_to_utf16(Span(API_METHODS[i].en), en) && names_equal((const u16*)name, n, en)) return i;
            if (utf8_to_utf16(Span(API_METHODS[i].ru), ru) && names_equal((const u16*)name, n, ru)) return i;
        }
        return -1;
    }
    const WCHAR_T* GetMethodName(const long num, const long alias) override {
        if (num < 0 || num >= API_METHOD_COUNT) return 0;
        Vec<u16> w;
        if (!utf8_to_utf16(Span(alias == 1 ? API_METHODS[num].ru : API_METHODS[num].en), w)) return 0;
        return NativeHost::alloc_wstr(mem_, w.d, w.n);
    }
    long GetNParams(const long num) override {
        return (num >= 0 && num < API_METHOD_COUNT) ? API_METHODS[num].nparams : 0;
    }
    bool GetParamDefValue(const long num, const long p, tVariant* v) override {
        if (!v) return false;
        if (num >= 0 && num < API_METHOD_COUNT && api_param_has_default((int)num, (int)p)) {
            WCHAR_T* s = NativeHost::alloc_wstr(mem_, 0, 0);
            if (!s) { var_init(v); return false; }
            var_init(v);
            v->pwstrVal = s;
            v->wstrLen = 0;
            v->vt = VTYPE_PWSTR;
            return true;
        }
        var_init(v);
        return false;
    }
    bool HasRetVal(const long num) override { return num >= 0 && num < API_METHOD_COUNT; }

    bool CallAsProc(const long num, tVariant* params, const long n) override {
        tVariant dummy;
        var_init(&dummy);
        bool ok = CallAsFunc(num, &dummy, params, n);
        release(&dummy);
        return ok;
    }

    bool CallAsFunc(const long num, tVariant* ret, tVariant* params, const long n) override {
        if (!ret || num < 0 || num >= API_METHOD_COUNT) return false;
        var_init(ret);
        NativeHost host(mem_, enc_, params, n, ret);
        u32 serial = st_.err_serial;
        if (n != API_METHODS[num].nparams || (n > 0 && !params)) {
            st_.set_error(WRAP_INVALID_PARAMETER_, "Неверное количество параметров метода.");
            host.put_int(-1, WRAP_INVALID_PARAMETER_);
            report(serial);
            return true;
        }
        for (long i = 0; i < n; ++i) {
            const tVariant* v = unref(&params[i]);
            if (!v || (v->vt & ~VTYPE_TYPEMASK)) {
                st_.set_error(WRAP_INVALID_PARAMETER_, "Некорректный параметр Native API.");
                host.put_int(-1, WRAP_INVALID_PARAMETER_);
                report(serial);
                return true;
            }
        }
        if (!api_call(st_, (int)num, host)) return false;
        if (host.failed) {
            st_.set_error(WRAP_MEMORY_ERROR_, "Не удалось выделить память 1С под результат.");
            release(ret);
            host.put_int(-1, WRAP_MEMORY_ERROR_);
        }
        report(serial);
        return true;
    }

    void SetLocale(const WCHAR_T*) override {}
    void SetUserInterfaceLanguageCode(const WCHAR_T*) override {}

private:
    IAddInDefBase* platform_;
    IMemoryManager* mem_;
    int enc_;
    ApiState st_;

    WCHAR_T* alloc_ascii(const char* s) {
        Vec<u16> w;
        if (!utf8_to_utf16(Span(s), w)) return 0;
        return NativeHost::alloc_wstr(mem_, w.d, w.n);
    }

    // Строки/BLOB, выделенные нами (возвращаемое значение процедуры), возвращаем менеджеру памяти.
    void release(tVariant* v) {
        if (!v || !mem_) return;
        if (v->vt == VTYPE_PWSTR && v->pwstrVal) mem_->FreeMemory((void**)&v->pwstrVal);
        else if ((v->vt == VTYPE_PSTR || v->vt == VTYPE_BLOB) && v->pstrVal) mem_->FreeMemory((void**)&v->pstrVal);
        var_init(v);
    }

    // Ошибки вызова компоненты (WRAP_*) дополнительно кладём в журнал регистрации 1С: вызывающий код мог не проверить результат.
    // Обычные ошибки криптографии (KCR_*) — только в код возврата и текст ошибки, как у KalkanCrypt.
    void report(u32 serial) {
        if (!platform_ || st_.err_serial == serial) return;
        u32 code = st_.err_code;
        if (code <= WRAP_BASE_ || code >= WRAP_BASE_ + 0x10000) return;
        Vec<u16> w;
        if (!utf8_to_utf16_lossy(st_.err_text.span(), w) || !w.push(0)) return;
        platform_->AddError((unsigned short)ADDIN_E_FAIL, kExtensionName, (const WCHAR_T*)w.d, (long)code);
    }
};

}  // namespace
}  // namespace nek

extern "C" {

__declspec(dllexport) const WCHAR_T* GetClassNames() { return nek::kClassNames; }

__declspec(dllexport) long GetClassObject(const WCHAR_T*, IComponentBase** pIntf) {
    // Имя класса не проверяем: платформа в некоторых режимах передаёт идентификатор подключения, а не имя класса.
    if (!pIntf) return 0;
    if (*pIntf) return 1;
    void* mem = nek::xalloc(sizeof(nek::Component));
    if (!mem) return 0;
    *pIntf = new (mem) nek::Component();
    return 1;
}

__declspec(dllexport) long DestroyObject(IComponentBase** pIntf) {
    if (!pIntf || !*pIntf) return 1;
    nek::Component* c = static_cast<nek::Component*>(*pIntf);
    c->~Component();
    nek::xfree(c);
    *pIntf = 0;
    return 0;
}

__declspec(dllexport) AppCapabilities SetPlatformCapabilities(const AppCapabilities capabilities) {
    return capabilities <= eAppCapabilitiesLast ? capabilities : eAppCapabilitiesLast;
}

__declspec(dllexport) AttachType GetAttachType() { return eCanAttachAny; }

}  // extern "C"
