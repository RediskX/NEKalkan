// NEKalkan — кодировки.
#include "codec.h"

namespace nek {

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

bool b64_encode(Span in, Bytes& out, size_t line_len, const char* eol) {
    size_t col = 0;
    size_t eol_len = cstrlen(eol);
    for (size_t i = 0; i < in.n; i += 3) {
        u32 v = (u32)in.p[i] << 16;
        if (i + 1 < in.n) v |= (u32)in.p[i + 1] << 8;
        if (i + 2 < in.n) v |= in.p[i + 2];
        char q[4] = {B64[(v >> 18) & 63], B64[(v >> 12) & 63],
                     i + 1 < in.n ? B64[(v >> 6) & 63] : '=', i + 2 < in.n ? B64[v & 63] : '='};
        for (int k = 0; k < 4; ++k) {
            if (line_len && col == line_len) {
                if (!out.append(eol, eol_len)) return false;
                col = 0;
            }
            if (!out.push((u8)q[k])) return false;
            ++col;
        }
    }
    return out.reserve(out.n);
}

bool b64_decode(Span in, Bytes& out) {
    u32 acc = 0;
    int bits = 0;
    size_t pad = 0, data_chars = 0;
    for (size_t i = 0; i < in.n; ++i) {
        u8 c = in.p[i];
        int v;
        if (c >= 'A' && c <= 'Z') v = c - 'A';
        else if (c >= 'a' && c <= 'z') v = c - 'a' + 26;
        else if (c >= '0' && c <= '9') v = c - '0' + 52;
        else if (c == '+' || c == '-') v = 62;          // допускаем url-safe
        else if (c == '/' || c == '_') v = 63;
        else if (c == '=') { ++pad; continue; }
        else if (c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;
        else return false;
        if (pad) return false;                          // данные после «=»
        ++data_chars;
        acc = (acc << 6) | (u32)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (!out.push((u8)(acc >> bits))) return false;
        }
    }
    if (pad > 2) return false;
    if (data_chars % 4 == 1) return false;              // невозможная длина
    // остаток битов должен быть нулевым (строгая проверка не нужна, терпим)
    return true;
}

bool b64_decode_strict(Span in, Bytes& out) {
    size_t n = 0, pad = 0;
    for (size_t i = 0; i < in.n; ++i) {
        u8 c = in.p[i];
        if (c == 0x0D || c == 0x0A) continue;
        if (c == '=') { ++pad; ++n; continue; }
        if (pad) return false;
        bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/';
        if (!ok) return false;
        ++n;
    }
    if (n % 4 != 0 || pad > 2) return false;
    return b64_decode(in, out);
}

static bool find_str(Span hay, const char* needle, size_t from, size_t& pos) {
    size_t nl = cstrlen(needle);
    if (hay.n < nl) return false;
    for (size_t i = from; i + nl <= hay.n; ++i)
        if (mem_eq(hay.p + i, needle, nl)) { pos = i; return true; }
    return false;
}

bool looks_like_pem(Span in) {
    size_t pos;
    return find_str(in, "-----BEGIN ", 0, pos);
}

bool pem_decode(Span in, Bytes& out, Bytes* out_label) {
    size_t b;
    if (!find_str(in, "-----BEGIN ", 0, b)) return false;
    size_t lab = b + 11, e = lab;
    while (e + 5 <= in.n && !mem_eq(in.p + e, "-----", 5)) ++e;
    if (e + 5 > in.n) return false;
    if (out_label) { out_label->clear(); if (!out_label->append(in.p + lab, e - lab)) return false; }
    size_t body = e + 5;
    size_t end_pos;
    if (!find_str(in, "-----END ", body, end_pos)) return false;
    return b64_decode(Span(in.p + body, end_pos - body), out);
}

bool pem_encode(Span der, const char* label, Bytes& out) {
    if (!out.append_str("-----BEGIN ") || !out.append_str(label) || !out.append_str("-----\n")) return false;
    if (!b64_encode(der, out, 64, "\n")) return false;
    if (!out.append_str("\n-----END ") || !out.append_str(label) || !out.append_str("-----\n")) return false;
    return true;
}

void hex_encode(Span in, Bytes& out, bool upper) {
    const char* d = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    for (size_t i = 0; i < in.n; ++i) {
        out.push((u8)d[in.p[i] >> 4]);
        out.push((u8)d[in.p[i] & 15]);
    }
}

// ---- Unicode ---------------------------------------------------------------

bool utf8_to_utf16(Span s, Vec<u16>& out) {
    size_t i = 0;
    while (i < s.n) {
        u32 c = s.p[i];
        int extra = 0;
        if (c < 0x80) extra = 0;
        else if ((c & 0xE0) == 0xC0) { c &= 0x1F; extra = 1; }
        else if ((c & 0xF0) == 0xE0) { c &= 0x0F; extra = 2; }
        else if ((c & 0xF8) == 0xF0) { c &= 0x07; extra = 3; }
        else return false;
        if (extra && i + extra >= s.n) return false;
        for (int k = 1; k <= extra; ++k) {
            if ((s.p[i + k] & 0xC0) != 0x80) return false;
            c = (c << 6) | (s.p[i + k] & 0x3F);
        }
        i += 1 + extra;
        if (c >= 0x10000) {
            c -= 0x10000;
            if (!out.push((u16)(0xD800 | (c >> 10))) || !out.push((u16)(0xDC00 | (c & 0x3FF)))) return false;
        } else {
            if (!out.push((u16)c)) return false;
        }
    }
    return true;
}

// Разбор одного символа; возвращает длину в байтах или 0, если последовательность недопустима.
static int utf8_char(Span s, size_t i, u32& cp) {
    u32 c = s.p[i];
    if (c < 0x80) { cp = c; return 1; }
    int extra;
    u32 lo;
    if (c >= 0xC2 && c <= 0xDF) { extra = 1; cp = c & 0x1F; lo = 0x80; }
    else if ((c & 0xF0) == 0xE0) { extra = 2; cp = c & 0x0F; lo = 0x800; }
    else if (c >= 0xF0 && c <= 0xF4) { extra = 3; cp = c & 0x07; lo = 0x10000; }
    else return 0;
    if (i + (size_t)extra >= s.n) return 0;
    for (int k = 1; k <= extra; ++k) {
        u32 b = s.p[i + (size_t)k];
        if ((b & 0xC0) != 0x80) return 0;
        cp = (cp << 6) | (b & 0x3F);
    }
    if (cp < lo || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return 0;
    return extra + 1;
}

bool utf8_valid(Span s) {
    size_t i = 0;
    while (i < s.n) {
        u32 cp;
        int l = utf8_char(s, i, cp);
        if (!l) return false;
        i += (size_t)l;
    }
    return true;
}

bool utf8_to_utf16_lossy(Span s, Vec<u16>& out) {
    size_t i = 0;
    while (i < s.n) {
        u32 cp;
        int l = utf8_char(s, i, cp);
        if (!l) { cp = 0xFFFD; l = 1; }
        i += (size_t)l;
        if (cp >= 0x10000) {
            cp -= 0x10000;
            if (!out.push((u16)(0xD800 | (cp >> 10))) || !out.push((u16)(0xDC00 | (cp & 0x3FF)))) return false;
        } else if (!out.push((u16)cp)) return false;
    }
    return true;
}

bool utf16_to_utf8(const u16* w, size_t n, Bytes& out) {
    for (size_t i = 0; i < n; ++i) {
        u32 c = w[i];
        if (c >= 0xD800 && c < 0xDC00) {
            if (i + 1 >= n || w[i + 1] < 0xDC00 || w[i + 1] > 0xDFFF) return false;
            c = 0x10000 + ((c - 0xD800) << 10) + (w[i + 1] - 0xDC00);
            ++i;
        } else if (c >= 0xDC00 && c <= 0xDFFF) {
            return false;
        }
        if (c < 0x80) { if (!out.push((u8)c)) return false; }
        else if (c < 0x800) { if (!out.push((u8)(0xC0 | (c >> 6))) || !out.push((u8)(0x80 | (c & 0x3F)))) return false; }
        else if (c < 0x10000) {
            if (!out.push((u8)(0xE0 | (c >> 12))) || !out.push((u8)(0x80 | ((c >> 6) & 0x3F))) || !out.push((u8)(0x80 | (c & 0x3F)))) return false;
        } else {
            if (!out.push((u8)(0xF0 | (c >> 18))) || !out.push((u8)(0x80 | ((c >> 12) & 0x3F))) ||
                !out.push((u8)(0x80 | ((c >> 6) & 0x3F))) || !out.push((u8)(0x80 | (c & 0x3F)))) return false;
        }
    }
    return true;
}

// Таблица CP1251 для 0x80..0xBF → Unicode (0xC0..0xFF = U+0410..U+044F)
static const u16 CP1251_HI[64] = {
    0x0402, 0x0403, 0x201A, 0x0453, 0x201E, 0x2026, 0x2020, 0x2021, 0x20AC, 0x2030, 0x0409, 0x2039, 0x040A, 0x040C, 0x040B, 0x040F,
    0x0452, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014, 0x0098, 0x2122, 0x0459, 0x203A, 0x045A, 0x045C, 0x045B, 0x045F,
    0x00A0, 0x040E, 0x045E, 0x0408, 0x00A4, 0x0490, 0x00A6, 0x00A7, 0x0401, 0x00A9, 0x0404, 0x00AB, 0x00AC, 0x00AD, 0x00AE, 0x0407,
    0x00B0, 0x00B1, 0x0406, 0x0456, 0x0491, 0x00B5, 0x00B6, 0x00B7, 0x0451, 0x2116, 0x0454, 0x00BB, 0x0458, 0x0405, 0x0455, 0x0457};

bool cp1251_to_utf8(Span in, Bytes& out) {
    Vec<u16> w;
    for (size_t i = 0; i < in.n; ++i) {
        u8 c = in.p[i];
        u16 u = c < 0x80 ? c : (c < 0xC0 ? CP1251_HI[c - 0x80] : (u16)(0x0410 + (c - 0xC0)));
        if (!w.push(u)) return false;
    }
    return utf16_to_utf8(w.d, w.n, out);
}

bool utf8_to_cp1251(Span in, Bytes& out) {
    Vec<u16> w;
    if (!utf8_to_utf16(in, w)) return false;
    for (size_t i = 0; i < w.n; ++i) {
        u16 u = w.d[i];
        int c = -1;
        if (u < 0x80) c = u;
        else if (u >= 0x0410 && u <= 0x044F) c = 0xC0 + (u - 0x0410);
        else for (int k = 0; k < 64; ++k) if (CP1251_HI[k] == u) { c = 0x80 + k; break; }
        if (c < 0 || !out.push((u8)c)) return false;
    }
    return true;
}

// ---- время -------------------------------------------------------------------

i64 days_from_civil(i64 y, unsigned m, unsigned d) {
    y -= m <= 2;
    const i64 era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = (unsigned)(y - era * 400);
    const unsigned doy = (153 * (m > 2 ? m - 3 : m + 9) + 2) / 5 + d - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + (i64)doe - 719468;
}

i64 to_unix(const DateTime& t) {
    return days_from_civil(t.year, (unsigned)t.month, (unsigned)t.day) * 86400 + t.hour * 3600 + t.min * 60 + t.sec;
}

void from_unix(i64 secs, DateTime& t) {
    i64 days = secs / 86400;
    i64 rem = secs % 86400;
    if (rem < 0) { rem += 86400; --days; }
    t.hour = (int)(rem / 3600); t.min = (int)(rem % 3600 / 60); t.sec = (int)(rem % 60);
    days += 719468;
    const i64 era = (days >= 0 ? days : days - 146096) / 146097;
    const unsigned doe = (unsigned)(days - era * 146097);
    const unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    const i64 y = (i64)yoe + era * 400;
    const unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const unsigned mp = (5 * doy + 2) / 153;
    t.day = (int)(doy - (153 * mp + 2) / 5 + 1);
    t.month = (int)(mp < 10 ? mp + 3 : mp - 9);
    t.year = (int)(y + (t.month <= 2));
}

}  // namespace nek
