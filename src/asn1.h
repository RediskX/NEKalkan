// NEKalkan — ASN.1 DER: разбор, запись, OID, время; нормализация BER (неопределённая длина).
#pragma once
#include "rt.h"
#include "codec.h"

namespace nek {

// ---- теги -----------------------------------------------------------------------
enum : u32 {
    T_BOOLEAN = 0x01, T_INTEGER = 0x02, T_BITSTRING = 0x03, T_OCTETSTRING = 0x04, T_NULL = 0x05, T_OID = 0x06,
    T_ENUMERATED = 0x0A, T_UTF8 = 0x0C, T_SEQUENCE = 0x30, T_SET = 0x31, T_PRINTABLE = 0x13, T_T61 = 0x14,
    T_IA5 = 0x16, T_UTCTIME = 0x17, T_GENTIME = 0x18, T_BMP = 0x1E,
};
inline u32 ctx_cons(u32 n) { return 0xA0 | n; }   // [n] constructed (EXPLICIT / IMPLICIT constructed)
inline u32 ctx_prim(u32 n) { return 0x80 | n; }   // [n] primitive (IMPLICIT)

// ---- чтение ---------------------------------------------------------------------

struct Tlv {
    u32 tag;       // один октет тега (номера ≥ 31 не поддерживаются)
    Span hdr;      // T + L
    Span val;      // содержимое
    Span full() const { return Span(hdr.p, hdr.n + val.n); }
};

// Прочитать один TLV (определённая длина, минимальная форма длины не требуется) с начала s и сдвинуть s.
bool der_next(Span& s, Tlv& t);
// Как der_next, но не сдвигает.
bool der_peek(Span s, Tlv& t);
// Прочитать TLV с ожидаемым тегом.
bool der_expect(Span& s, u32 tag, Tlv& t);
// Пройти по детям содержимого constructed-элемента: вызывать, пока true. s — содержимое родителя.
inline bool der_more(const Span& s) { return s.n > 0; }

// BER → определённая длина (вложенные constructed тоже переписываются). Примитивы копируются как есть.
bool ber_to_der(Span in, Bytes& out);

// ---- OID --------------------------------------------------------------------------

// Содержимое OID → "1.2.3" (до 127 символов + 0). false при ошибке.
bool oid_to_str(Span content, char* out, size_t cap);
bool oid_is(Span content, const char* dotted);
// dotted → содержимое OID (без тега/длины)
bool oid_encode(const char* dotted, Bytes& out);

// ---- целые ---------------------------------------------------------------------------

// Содержимое INTEGER без ведущего нулевого байта знака (если число неотрицательно).
Span int_magnitude(Span content);
bool int_to_u64(Span content, u64& v);   // false, если отрицательное или не помещается

// ---- время ----------------------------------------------------------------------------

bool asn_time_parse(const Tlv& t, i64& unix_secs);                    // UTCTime / GeneralizedTime
bool asn_time_parse(u32 tag, Span val, i64& unix_secs);

// ---- запись -------------------------------------------------------------------------------
//
// Построение через begin/end: end() вычисляет длину и вставляет заголовок.
class DerOut {
public:
    Bytes b;
    bool begin(u32 tag);
    bool end();
    bool prim(u32 tag, Span content);
    bool raw(Span der) { return b.append(der); }
    bool oid(const char* dotted);
    bool integer_be(Span magnitude);                  // неотрицательное, big-endian
    bool integer_u64(u64 v);
    bool null() { return prim(T_NULL, Span()); }
    bool octets(Span s) { return prim(T_OCTETSTRING, s); }
    bool bitstring(Span s, int unused = 0);
    bool utf8(Span s) { return prim(T_UTF8, s); }
    bool printable(Span s) { return prim(T_PRINTABLE, s); }
    bool time(i64 unix_secs);                         // UTCTime до 2049, затем GeneralizedTime
    bool boolean(bool v);
    bool ok() const { return !failed_ && depth_ == 0; }
private:
    size_t starts_[24];
    u32 tags_[24];
    int depth_ = 0;
    bool failed_ = false;
};

// Обернуть готовое содержимое в TLV.
bool der_wrap(u32 tag, Span content, Bytes& out);
// Закодировать длину.
size_t der_len_bytes(size_t len, u8* out);

}  // namespace nek
