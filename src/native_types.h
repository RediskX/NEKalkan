// NEKalkan — типы и интерфейсы Native API 1С:Предприятия (внешние компоненты).
//
// Определены вручную (без windows.h и без официальных заголовков), порядок виртуальных методов и раскладка tVariant
// совпадают с официальными ComponentBase.h / AddInDefBase.h / IMemoryManager.h / types.h
// (копии лежат в third_party/1c_native_api). От порядка зависит совпадение vtable с объектами платформы.
#pragma once
#include "rt.h"

typedef char16_t WCHAR_T;

enum ENUMVAR {
    VTYPE_EMPTY = 0, VTYPE_NULL = 1, VTYPE_I2 = 2, VTYPE_I4 = 3, VTYPE_R4 = 4, VTYPE_R8 = 5, VTYPE_DATE = 6, VTYPE_TM = 7,
    VTYPE_PSTR = 8, VTYPE_INTERFACE = 9, VTYPE_ERROR = 10, VTYPE_BOOL = 11, VTYPE_VARIANT = 12, VTYPE_I1 = 13,
    VTYPE_UI1 = 14, VTYPE_UI2 = 15, VTYPE_UI4 = 16, VTYPE_I8 = 17, VTYPE_UI8 = 18, VTYPE_INT = 19, VTYPE_UINT = 20,
    VTYPE_HRESULT = 21, VTYPE_PWSTR = 22, VTYPE_BLOB = 23, VTYPE_CLSID = 24,
    VTYPE_STR_BLOB = 0x0fff, VTYPE_VECTOR = 0x1000, VTYPE_ARRAY = 0x2000, VTYPE_BYREF = 0x4000, VTYPE_RESERVED = 0x8000,
    VTYPE_TYPEMASK = 0x0fff
};

typedef unsigned short TYPEVAR;

struct NativeGuid { unsigned int Data1; unsigned short Data2; unsigned short Data3; unsigned char Data4[8]; };
struct NativeTm { int tm_sec, tm_min, tm_hour, tm_mday, tm_mon, tm_year, tm_wday, tm_yday, tm_isdst; };

struct tVariant {
    union {
        signed char i8Val;
        short shortVal;
        int lVal;
        int intVal;
        unsigned int uintVal;
        long long llVal;
        unsigned char ui8Val;
        unsigned short ushortVal;
        unsigned int ulVal;
        unsigned long long ullVal;
        int errCode;
        int hRes;
        float fltVal;
        double dblVal;
        bool bVal;
        char chVal;
        char16_t wchVal;
        double date;
        NativeGuid IDVal;
        tVariant* pvarVal;
        NativeTm tmVal;
        struct { void* pInterfaceVal; NativeGuid InterfaceID; };
        struct { char* pstrVal; unsigned int strLen; };
        struct { WCHAR_T* pwstrVal; unsigned int wstrLen; };
    };
    unsigned int cbElements;
    TYPEVAR vt;
};

class IMemoryManager {
public:
    virtual ~IMemoryManager() {}
    virtual bool AllocMemory(void** pMemory, unsigned long ulCountByte) = 0;
    virtual void FreeMemory(void** pMemory) = 0;
};

// Интерфейс платформы, передаваемый в IInitDoneBase::Init.
class IAddInDefBase {
public:
    virtual ~IAddInDefBase() {}
    virtual bool AddError(unsigned short wcode, const WCHAR_T* source, const WCHAR_T* descr, long scode) = 0;
    virtual bool Read(WCHAR_T* wszPropName, tVariant* pVal, long* pErrCode, WCHAR_T** errDescriptor) = 0;
    virtual bool Write(WCHAR_T* wszPropName, tVariant* pVar) = 0;
    virtual bool RegisterProfileAs(WCHAR_T* wszProfileName) = 0;
    virtual bool SetEventBufferDepth(long lDepth) = 0;
    virtual long GetEventBufferDepth() = 0;
    virtual bool ExternalEvent(WCHAR_T* wszSource, WCHAR_T* wszMessage, WCHAR_T* wszData) = 0;
    virtual void CleanEventBuffer() = 0;
    virtual bool SetStatusLine(WCHAR_T* wszStatusLine) = 0;
    virtual void ResetStatusLine() = 0;
};

#define ADDIN_E_FAIL 1006

class IInitDoneBase {
public:
    virtual ~IInitDoneBase() {}
    virtual bool Init(void* disp) = 0;
    virtual bool setMemManager(void* mem) = 0;
    virtual long GetInfo() = 0;
    virtual void Done() = 0;
};

class ILanguageExtenderBase {
public:
    virtual ~ILanguageExtenderBase() {}
    virtual bool RegisterExtensionAs(WCHAR_T** wsExtensionName) = 0;
    virtual long GetNProps() = 0;
    virtual long FindProp(const WCHAR_T* wsPropName) = 0;
    virtual const WCHAR_T* GetPropName(long lPropNum, long lPropAlias) = 0;
    virtual bool GetPropVal(const long lPropNum, tVariant* pvarPropVal) = 0;
    virtual bool SetPropVal(const long lPropNum, tVariant* varPropVal) = 0;
    virtual bool IsPropReadable(const long lPropNum) = 0;
    virtual bool IsPropWritable(const long lPropNum) = 0;
    virtual long GetNMethods() = 0;
    virtual long FindMethod(const WCHAR_T* wsMethodName) = 0;
    virtual const WCHAR_T* GetMethodName(const long lMethodNum, const long lMethodAlias) = 0;
    virtual long GetNParams(const long lMethodNum) = 0;
    virtual bool GetParamDefValue(const long lMethodNum, const long lParamNum, tVariant* pvarParamDefValue) = 0;
    virtual bool HasRetVal(const long lMethodNum) = 0;
    virtual bool CallAsProc(const long lMethodNum, tVariant* paParams, const long lSizeArray) = 0;
    virtual bool CallAsFunc(const long lMethodNum, tVariant* pvarRetValue, tVariant* paParams, const long lSizeArray) = 0;
};

class LocaleBase {
public:
    virtual ~LocaleBase() {}
    virtual void SetLocale(const WCHAR_T* loc) = 0;
};

class UserLanguageBase {
public:
    virtual ~UserLanguageBase() {}
    virtual void SetUserInterfaceLanguageCode(const WCHAR_T* lang) = 0;
};

class IComponentBase : public IInitDoneBase, public ILanguageExtenderBase, public LocaleBase, public UserLanguageBase {
public:
    virtual ~IComponentBase() {}
};

enum AppCapabilities {
    eAppCapabilitiesInvalid = -1,
    eAppCapabilities1 = 1,
    eAppCapabilities2 = 2,
    eAppCapabilities3 = 3,
    eAppCapabilitiesLast = eAppCapabilities3
};

enum AttachType { eCanAttachNotIsolated = 1, eCanAttachIsolated = 2, eCanAttachAny = 3 };
