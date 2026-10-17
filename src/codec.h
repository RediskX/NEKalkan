// NEKalkan — Base64, PEM, hex, UTF-8/UTF-16, время.
#pragma once
#include "rt.h"

namespace nek {

// Base64. line_len = 0 — без переносов; иначе перенос каждые line_len символов (eol — "\n" или "\r\n").
bool b64_encode(Span in, Bytes& out, size_t line_len = 0, const char* eol = "\n");
// Пробельные символы игнорируются; ошибка при недопустимых символах и неверной длине.
bool b64_decode(Span in, Bytes& out);
// Строгий вариант для входных данных API (как BIO base64 у KalkanCrypt): алфавит +/, только переводы строк между символами,
// длина кратна 4, «=» только в конце.
bool b64_decode_strict(Span in, Bytes& out);

// PEM: ищет первую пару -----BEGIN X----- / -----END X----- и декодирует тело. label (без дефисов) — в out_label.
bool pem_decode(Span in, Bytes& out, Bytes* out_label = 0);
bool pem_encode(Span der, const char* label, Bytes& out);   // строки по 64, перевод строки "\n"
bool looks_like_pem(Span in);

void hex_encode(Span in, Bytes& out, bool upper = true);

// UTF-8 <-> UTF-16 (little-endian слова u16).
bool utf8_to_utf16(Span utf8, Vec<u16>& out);
bool utf16_to_utf8(const u16* w, size_t n, Bytes& out);
// Строгая проверка UTF-8 (без overlong, суррогатов и значений выше U+10FFFF).
bool utf8_valid(Span s);
// Декодирование с заменой недопустимых байтов на U+FFFD (для показа текста в 1С).
bool utf8_to_utf16_lossy(Span utf8, Vec<u16>& out);
// CP1251 -> UTF-8 (для режимов обмена ACP/CP1251)
bool cp1251_to_utf8(Span in, Bytes& out);
bool utf8_to_cp1251(Span in, Bytes& out);        // false, если символ не представим

// Время: Unix-секунды (UTC) <-> календарь.
struct DateTime { int year, month, day, hour, min, sec; };
i64 days_from_civil(i64 y, unsigned m, unsigned d);
i64 to_unix(const DateTime& t);
void from_unix(i64 secs, DateTime& t);

}  // namespace nek
