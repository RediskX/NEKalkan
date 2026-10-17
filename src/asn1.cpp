// NEKalkan — ASN.1 DER.
#include "asn1.h"

namespace nek {

// ---- чтение ---------------------------------------------------------------------

bool der_peek(Span s, Tlv& t) {
    if (s.n < 2) return false;
    u32 tag = s.p[0];
    if ((tag & 0x1F) == 0x1F) return false;
    size_t pos = 1;
    size_t len = s.p[pos++];
    if (len & 0x80) {
        size_t nb = len & 0x7F;
        if (nb == 0 || nb > 4 || pos + nb > s.n) return false;   // неопределённая длина — через ber_to_der
        len = 0;
        for (size_t i = 0; i < nb; ++i) len = (len << 8) | s.p[pos++];
    }
    if (len > s.n - pos) return false;
    t.tag = tag;
    t.hdr = Span(s.p, pos);
    t.val = Span(s.p + pos, len);
    return true;
}

bool der_next(Span& s, Tlv& t) {
    if (!der_peek(s, t)) return false;
    size_t used = t.hdr.n + t.val.n;
    s.p += used;
    s.n -= used;
    return true;
}

bool der_expect(Span& s, u32 tag, Tlv& t) {
    Span save = s;
    if (!der_next(s, t) || t.tag != tag) { s = save; return false; }
    return true;
}

// ---- BER → DER -------------------------------------------------------------------

static size_t put_len(u8* o, size_t len) {
    if (len < 0x80) { o[0] = (u8)len; return 1; }
    u8 tmp[8];
    int k = 0;
    while (len) { tmp[k++] = (u8)len; len >>= 8; }
    o[0] = (u8)(0x80 | k);
    for (int i = 0; i < k; ++i) o[1 + i] = tmp[k - 1 - i];
    return 1 + k;
}

size_t der_len_bytes(size_t len, u8* out) { return put_len(out, len); }

// Читает один BER-элемент с позиции pos, пишет его DER-форму в out, возвращает новую позицию (или (size_t)-1).
static size_t ber_elem(Span in, size_t pos, Bytes& out, int depth) {
    if (depth > 32 || pos + 2 > in.n) return (size_t)-1;
    u32 tag = in.p[pos++];
    if ((tag & 0x1F) == 0x1F) return (size_t)-1;
    size_t len = in.p[pos++];
    bool indef = false;
    if (len == 0x80) indef = true;
    else if (len & 0x80) {
        size_t nb = len & 0x7F;
        if (nb > 4 || pos + nb > in.n) return (size_t)-1;
        len = 0;
        for (size_t i = 0; i < nb; ++i) len = (len << 8) | in.p[pos++];
    }
    if (!(tag & 0x20)) {                                    // примитив
        if (indef || len > in.n - pos) return (size_t)-1;
        u8 lb[10];
        size_t ll = put_len(lb, len);
        if (!out.push((u8)tag) || !out.append(lb, ll) || !out.append(in.p + pos, len)) return (size_t)-1;
        return pos + len;
    }
    // constructed: переписываем детей во временный буфер
    Bytes body;
    size_t end = indef ? in.n : pos + len;
    if (!indef && len > in.n - pos) return (size_t)-1;
    size_t p = pos;
    if (indef) {
        for (;;) {
            if (p + 2 > in.n) return (size_t)-1;
            if (in.p[p] == 0 && in.p[p + 1] == 0) { p += 2; break; }
            p = ber_elem(in, p, body, depth + 1);
            if (p == (size_t)-1) return p;
        }
    } else {
        while (p < end) {
            p = ber_elem(Span(in.p, end), p, body, depth + 1);
            if (p == (size_t)-1) return p;
        }
    }
    u8 lb[10];
    size_t ll = put_len(lb, body.n);
    if (!out.push((u8)tag) || !out.append(lb, ll) || !out.append(body.p, body.n)) return (size_t)-1;
    return p;
}

bool ber_to_der(Span in, Bytes& out) {
    // Ожидается один элемент верхнего уровня; хвост после него (перевод строки, нули) игнорируется — как у asn1crypto.
    size_t pos = ber_elem(in, 0, out, 0);
    return pos != (size_t)-1;
}

// ---- OID ---------------------------------------------------------------------------

bool oid_to_str(Span c, char* out, size_t cap) {
    if (c.n == 0 || cap < 8) return false;
    size_t o = 0;
    auto put_num = [&](u64 v) -> bool {
        char tmp[24];
        int k = 0;
        if (v == 0) tmp[k++] = '0';
        while (v) { tmp[k++] = (char)('0' + v % 10); v /= 10; }
        if (o + k + 1 >= cap) return false;
        while (k) out[o++] = tmp[--k];
        return true;
    };
    u64 first = c.p[0];
    u64 a = first / 40 > 2 ? 2 : first / 40;
    if (!put_num(a)) return false;
    out[o++] = '.';
    // для a == 2 второй компонент может быть > 39; одна цифра x - 80 — только если первый байт един
    u64 acc = 0;
    size_t i = 1;
    u64 second = first - a * 40;
    if (!put_num(second)) return false;
    for (; i < c.n; ++i) {
        acc = (acc << 7) | (c.p[i] & 0x7F);
        if (!(c.p[i] & 0x80)) {
            if (o + 2 >= cap) return false;
            out[o++] = '.';
            if (!put_num(acc)) return false;
            acc = 0;
        } else if (i + 1 == c.n) {
            return false;
        }
    }
    out[o] = 0;
    return true;
}

bool oid_is(Span content, const char* dotted) {
    char buf[128];
    if (!oid_to_str(content, buf, sizeof(buf))) return false;
    size_t i = 0;
    while (buf[i] && dotted[i] && buf[i] == dotted[i]) ++i;
    return buf[i] == 0 && dotted[i] == 0;
}

bool oid_encode(const char* dotted, Bytes& out) {
    u64 parts[32];
    int np = 0;
    const char* p = dotted;
    while (*p) {
        u64 v = 0;
        if (*p < '0' || *p > '9') return false;
        while (*p >= '0' && *p <= '9') v = v * 10 + (u64)(*p++ - '0');
        if (np >= 32) return false;
        parts[np++] = v;
        if (*p == '.') ++p;
        else if (*p) return false;
    }
    if (np < 2) return false;
    if (!out.push((u8)(parts[0] * 40 + parts[1]))) return false;
    for (int i = 2; i < np; ++i) {
        u8 tmp[10];
        int k = 0;
        u64 v = parts[i];
        do { tmp[k++] = (u8)(v & 0x7F); v >>= 7; } while (v);
        for (int j = k - 1; j >= 0; --j)
            if (!out.push((u8)(tmp[j] | (j ? 0x80 : 0)))) return false;
    }
    return true;
}

// ---- целые ----------------------------------------------------------------------------

Span int_magnitude(Span c) {
    while (c.n > 1 && c.p[0] == 0) { c.p++; c.n--; }
    return c;
}

bool int_to_u64(Span c, u64& v) {
    if (c.n == 0 || (c.p[0] & 0x80)) return false;
    c = int_magnitude(c);
    if (c.n > 8) return false;
    v = 0;
    for (size_t i = 0; i < c.n; ++i) v = (v << 8) | c.p[i];
    return true;
}

// ---- время -------------------------------------------------------------------------------

static bool digits(const u8* p, int n, int& v) {
    v = 0;
    for (int i = 0; i < n; ++i) {
        if (p[i] < '0' || p[i] > '9') return false;
        v = v * 10 + (p[i] - '0');
    }
    return true;
}

bool asn_time_parse(u32 tag, Span s, i64& out) {
    DateTime t;
    size_t pos = 0;
    int yy;
    if (tag == T_UTCTIME) {
        if (s.n < 11 || !digits(s.p, 2, yy)) return false;
        t.year = yy < 50 ? 2000 + yy : 1900 + yy;
        pos = 2;
    } else if (tag == T_GENTIME) {
        if (s.n < 13 || !digits(s.p, 4, t.year)) return false;
        pos = 4;
    } else {
        return false;
    }
    if (!digits(s.p + pos, 2, t.month) || !digits(s.p + pos + 2, 2, t.day) ||
        !digits(s.p + pos + 4, 2, t.hour) || !digits(s.p + pos + 6, 2, t.min)) return false;
    pos += 8;
    t.sec = 0;
    if (pos + 2 <= s.n && s.p[pos] >= '0' && s.p[pos] <= '9') {
        if (!digits(s.p + pos, 2, t.sec)) return false;
        pos += 2;
    }
    if (pos < s.n && s.p[pos] == '.') { ++pos; while (pos < s.n && s.p[pos] >= '0' && s.p[pos] <= '9') ++pos; }
    i64 off = 0;
    if (pos < s.n && (s.p[pos] == '+' || s.p[pos] == '-')) {
        int hh, mm;
        if (pos + 5 > s.n || !digits(s.p + pos + 1, 2, hh) || !digits(s.p + pos + 3, 2, mm)) return false;
        off = (hh * 3600 + mm * 60) * (s.p[pos] == '+' ? 1 : -1);
        pos += 5;
    } else if (pos < s.n && s.p[pos] == 'Z') {
        ++pos;
    } else {
        return false;
    }
    if (pos != s.n) return false;
    if (t.month < 1 || t.month > 12 || t.day < 1 || t.day > 31 || t.hour > 23 || t.min > 59 || t.sec > 60) return false;
    out = to_unix(t) - off;
    return true;
}

bool asn_time_parse(const Tlv& t, i64& out) { return asn_time_parse(t.tag, t.val, out); }

// ---- запись ----------------------------------------------------------------------------------

bool DerOut::begin(u32 tag) {
    if (failed_ || depth_ >= 24) { failed_ = true; return false; }
    starts_[depth_] = b.n;
    tags_[depth_] = tag;
    ++depth_;
    return true;
}

bool DerOut::end() {
    if (failed_ || depth_ <= 0) { failed_ = true; return false; }
    --depth_;
    size_t start = starts_[depth_];
    size_t len = b.n - start;
    u8 hdr[10];
    hdr[0] = (u8)tags_[depth_];
    size_t hl = 1 + put_len(hdr + 1, len);
    size_t old = b.n;
    if (!b.resize(old + hl)) { failed_ = true; return false; }
    memmove(b.p + start + hl, b.p + start, len);
    memcpy(b.p + start, hdr, hl);
    return true;
}

bool DerOut::prim(u32 tag, Span c) {
    if (failed_) return false;
    u8 hdr[10];
    hdr[0] = (u8)tag;
    size_t hl = 1 + put_len(hdr + 1, c.n);
    if (!b.append(hdr, hl) || !b.append(c.p, c.n)) { failed_ = true; return false; }
    return true;
}

bool DerOut::oid(const char* dotted) {
    Bytes c;
    if (!oid_encode(dotted, c)) { failed_ = true; return false; }
    return prim(T_OID, c.span());
}

bool DerOut::integer_be(Span mag) {
    while (mag.n > 1 && mag.p[0] == 0) { mag.p++; mag.n--; }
    Bytes c;
    if (mag.n == 0) { if (!c.push(0)) { failed_ = true; return false; } }
    else {
        if ((mag.p[0] & 0x80) && !c.push(0)) { failed_ = true; return false; }
        if (!c.append(mag)) { failed_ = true; return false; }
    }
    return prim(T_INTEGER, c.span());
}

bool DerOut::integer_u64(u64 v) {
    u8 tmp[8];
    for (int i = 7; i >= 0; --i) { tmp[i] = (u8)v; v >>= 8; }
    return integer_be(Span(tmp, 8));
}

bool DerOut::bitstring(Span s, int unused) {
    Bytes c;
    if (!c.push((u8)unused) || !c.append(s)) { failed_ = true; return false; }
    return prim(T_BITSTRING, c.span());
}

bool DerOut::boolean(bool v) {
    u8 x = v ? 0xFF : 0;
    return prim(T_BOOLEAN, Span(&x, 1));
}

bool DerOut::time(i64 secs) {
    DateTime t;
    from_unix(secs, t);
    char buf[20];
    size_t n = 0;
    auto put2 = [&](int v) { buf[n++] = (char)('0' + v / 10 % 10); buf[n++] = (char)('0' + v % 10); };
    u32 tag;
    if (t.year >= 1950 && t.year < 2050) { put2(t.year % 100); tag = T_UTCTIME; }
    else { put2(t.year / 100); put2(t.year % 100); tag = T_GENTIME; }
    put2(t.month); put2(t.day); put2(t.hour); put2(t.min); put2(t.sec);
    buf[n++] = 'Z';
    return prim(tag, Span((const u8*)buf, n));
}

bool der_wrap(u32 tag, Span content, Bytes& out) {
    u8 hdr[10];
    hdr[0] = (u8)tag;
    size_t hl = 1 + put_len(hdr + 1, content.n);
    return out.append(hdr, hl) && out.append(content);
}

}  // namespace nek
