// NEKalkan — XML: разбор, C14N, сериализация.
#include "xml.h"

namespace nek {

const char* const XML_NS = "http://www.w3.org/XML/1998/namespace";
const char* const DS_NS = "http://www.w3.org/2000/09/xmldsig#";

// ---- узлы и арена ---------------------------------------------------------------

XDoc::~XDoc() {
    for (size_t i = 0; i < all.n; ++i) delete all.d[i];
    for (size_t i = 0; i < chunks.n; ++i) delete chunks.d[i];
}

XNode* XDoc::new_node(XKind k) {
    XNode* n = new XNode();
    if (!n) return 0;
    n->kind = k;
    if (!all.push(n)) { delete n; return 0; }
    return n;
}

Span XDoc::intern(Span s) {
    if (s.n == 0) return Span((const u8*)"", 0);
    Bytes* c = chunks.n ? chunks.d[chunks.n - 1] : 0;
    if (!c || c->n + s.n > c->cap) {
        c = new Bytes();
        if (!c) return Span();
        size_t want = s.n > 65536 ? s.n : 65536;
        if (!c->reserve(want) || !chunks.push(c)) { delete c; return Span(); }
    }
    size_t at = c->n;
    c->append(s.p, s.n);                 // capacity гарантирована: перераспределения нет
    return Span(c->p + at, s.n);
}

void XDoc::append(XNode* parent, XNode* child) {
    child->parent = parent;
    child->prev = parent->last;
    child->next = 0;
    if (parent->last) parent->last->next = child; else parent->first = child;
    parent->last = child;
}

static bool span_eq_cstr(Span s, const char* c) {
    size_t n = cstrlen(c);
    return s.n == n && mem_eq(s.p, c, n);
}

const XAttr* XNode::attr(const char* q) const {
    for (size_t i = 0; i < attrs.n; ++i) if (span_eq_cstr(attrs.d[i].qname, q)) return &attrs.d[i];
    return 0;
}
const XAttr* XNode::attr_local(const char* l) const {
    for (size_t i = 0; i < attrs.n; ++i)
        if (attrs.d[i].ns.n == 0 && span_eq_cstr(attrs.d[i].local, l)) return &attrs.d[i];
    return 0;
}

static const XNode* dfs_find(const XNode* n, Span local, Span ns) {
    for (const XNode* c = n->first; c; c = c->next) {
        if (c->kind != XK_ELEM) continue;
        if (c->local.eq(local) && c->ns.eq(ns)) return c;
        const XNode* r = dfs_find(c, local, ns);
        if (r) return r;
    }
    return 0;
}

const XNode* XDoc::find_element(const XNode* from, Span local, Span ns) const {
    if (!from) from = doc;
    if (from->kind == XK_ELEM && from->local.eq(local) && from->ns.eq(ns)) return from;
    return dfs_find(from, local, ns);
}

// Ищет все элементы с данным Id; found считает совпадения (дубликат Id делает ссылку неоднозначной — защита от XML Signature Wrapping).
static void dfs_id(const XNode* n, Span id, const XNode*& first, int& found) {
    for (const XNode* c = n->first; c && found < 2; c = c->next) {
        if (c->kind != XK_ELEM) continue;
        for (size_t i = 0; i < c->attrs.n; ++i) {
            const XAttr& a = c->attrs.d[i];
            if (a.ns.n == 0 && (span_eq_cstr(a.qname, "Id") || span_eq_cstr(a.qname, "ID")) && a.value.eq(id)) {
                if (!found) first = c;
                ++found;
                break;
            }
        }
        dfs_id(c, id, first, found);
    }
}

bool XDoc::id_exists(Span id) const {
    const XNode* first = 0;
    int found = 0;
    dfs_id(doc, id, first, found);
    return found > 0;
}

const XNode* XDoc::find_by_id(Span id) const {
    const XNode* first = 0;
    int found = 0;
    dfs_id(doc, id, first, found);
    return found == 1 ? first : 0;      // нет такого узла или Id неоднозначен
}

// ---- разбор ----------------------------------------------------------------------------

namespace {

struct Parser {
    XDoc& d;
    Span s;
    size_t pos;
    Parser(XDoc& dd, Span ss) : d(dd), s(ss), pos(0) {}

    bool eof() const { return pos >= s.n; }
    bool starts(const char* t) const {
        size_t n = cstrlen(t);
        return pos + n <= s.n && mem_eq(s.p + pos, t, n);
    }
    static bool is_ws(u8 c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }
    void skip_ws() { while (pos < s.n && is_ws(s.p[pos])) ++pos; }
    static bool is_name_end(u8 c) { return is_ws(c) || c == '=' || c == '/' || c == '>' || c == '<' || c == '"' || c == '\'' || c == '?' ; }

    bool encode_cp(u32 cp, Bytes& out) {
        if (cp == 0 || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return false;
        if (cp < 0x80) return out.push((u8)cp);
        if (cp < 0x800) return out.push((u8)(0xC0 | (cp >> 6))) && out.push((u8)(0x80 | (cp & 0x3F)));
        if (cp < 0x10000) return out.push((u8)(0xE0 | (cp >> 12))) && out.push((u8)(0x80 | ((cp >> 6) & 0x3F))) && out.push((u8)(0x80 | (cp & 0x3F)));
        return out.push((u8)(0xF0 | (cp >> 18))) && out.push((u8)(0x80 | ((cp >> 12) & 0x3F))) &&
               out.push((u8)(0x80 | ((cp >> 6) & 0x3F))) && out.push((u8)(0x80 | (cp & 0x3F)));
    }

    // pos указывает на '&'; декодирует ссылку и сдвигает pos
    bool decode_ref(Bytes& out) {
        size_t i = pos + 1, e = i;
        while (e < s.n && e - i <= 12 && s.p[e] != ';') ++e;
        if (e >= s.n || s.p[e] != ';') return false;
        Span name(s.p + i, e - i);
        pos = e + 1;
        if (span_eq_cstr(name, "lt")) return out.push('<');
        if (span_eq_cstr(name, "gt")) return out.push('>');
        if (span_eq_cstr(name, "amp")) return out.push('&');
        if (span_eq_cstr(name, "quot")) return out.push('"');
        if (span_eq_cstr(name, "apos")) return out.push('\'');
        if (name.n >= 2 && name.p[0] == '#') {
            u32 cp = 0;
            if (name.p[1] == 'x' || name.p[1] == 'X') {
                if (name.n < 3) return false;
                for (size_t k = 2; k < name.n; ++k) {
                    u8 c = name.p[k];
                    int v = c >= '0' && c <= '9' ? c - '0' : (c >= 'a' && c <= 'f' ? c - 'a' + 10 : (c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1));
                    if (v < 0) return false;
                    cp = cp * 16 + (u32)v;
                    if (cp > 0x10FFFF) return false;
                }
            } else {
                for (size_t k = 1; k < name.n; ++k) {
                    if (name.p[k] < '0' || name.p[k] > '9') return false;
                    cp = cp * 10 + (u32)(name.p[k] - '0');
                    if (cp > 0x10FFFF) return false;
                }
            }
            return encode_cp(cp, out);
        }
        return false;                           // неизвестная сущность
    }

    // Текст до '<' (контент): нормализация концов строк и ссылки
    bool read_text(Bytes& out) {
        while (pos < s.n && s.p[pos] != '<') {
            u8 c = s.p[pos];
            if (c == '&') { if (!decode_ref(out)) return false; }
            else if (c == '\r') { out.push('\n'); ++pos; if (pos < s.n && s.p[pos] == '\n') ++pos; }
            else { out.push(c); ++pos; }
        }
        return true;
    }

    bool read_attr_value(u8 quote, Bytes& out) {
        while (pos < s.n && s.p[pos] != quote) {
            u8 c = s.p[pos];
            if (c == '<') return false;
            if (c == '&') { if (!decode_ref(out)) return false; }
            else if (c == '\r') { out.push(' '); ++pos; if (pos < s.n && s.p[pos] == '\n') ++pos; }
            else if (c == '\n' || c == '\t') { out.push(' '); ++pos; }
            else { out.push(c); ++pos; }
        }
        if (pos >= s.n) return false;
        ++pos;                                  // закрывающая кавычка
        return true;
    }

    Span read_name() {
        size_t b = pos;
        while (pos < s.n && !is_name_end(s.p[pos])) ++pos;
        return Span(s.p + b, pos - b);
    }
};

const Span* lookup_decl(const XNode* e, Span prefix) {
    for (const XNode* n = e; n; n = n->parent)
        for (size_t i = 0; i < n->nsdecls.n; ++i)
            if (n->nsdecls.d[i].prefix.eq(prefix)) return &n->nsdecls.d[i].uri;
    return 0;
}

void split_qname(Span q, Span& prefix, Span& local) {
    for (size_t i = 0; i < q.n; ++i)
        if (q.p[i] == ':') { prefix = Span(q.p, i); local = Span(q.p + i + 1, q.n - i - 1); return; }
    prefix = Span(q.p, 0);
    local = q;
}

}  // namespace

bool XDoc::parse(Span in, bool assume_utf8) {
    // 1. кодировка → UTF-8 в собственной копии
    Bytes conv;
    Span src = in;
    if (src.n >= 3 && src.p[0] == 0xEF && src.p[1] == 0xBB && src.p[2] == 0xBF) { src.p += 3; src.n -= 3; }
    else if (src.n >= 2 && ((src.p[0] == 0xFF && src.p[1] == 0xFE) || (src.p[0] == 0xFE && src.p[1] == 0xFF))) {
        bool le = src.p[0] == 0xFF;
        Vec<u16> w;
        for (size_t i = 2; i + 1 < src.n; i += 2)
            if (!w.push(le ? (u16)(src.p[i] | (src.p[i + 1] << 8)) : (u16)((src.p[i] << 8) | src.p[i + 1]))) return false;
        if (!utf16_to_utf8(w.d, w.n, conv)) return false;
        src = conv.span();
    } else {
        // объявленная кодировка
        size_t lim = src.n < 200 ? src.n : 200;
        if (!assume_utf8 && lim > 20 && mem_eq(src.p, "<?xml", 5)) {
            for (size_t i = 5; i + 9 < lim; ++i) {
                if (mem_eq(src.p + i, "encoding", 8)) {
                    size_t j = i + 8;
                    while (j < lim && (src.p[j] == ' ' || src.p[j] == '=')) ++j;
                    if (j < lim && (src.p[j] == '"' || src.p[j] == '\'')) {
                        size_t k = j + 1;
                        char name[24];
                        size_t nl = 0;
                        while (k < lim && src.p[k] != src.p[j] && nl < 23) {
                            char ch = (char)src.p[k++];
                            name[nl++] = (ch >= 'A' && ch <= 'Z') ? (char)(ch + 32) : ch;
                        }
                        name[nl] = 0;
                        if (!cstrlen(name)) break;
                        bool win = (nl == 12 && mem_eq(name, "windows-1251", 12)) || (nl == 6 && mem_eq(name, "cp1251", 6)) ||
                                   (nl == 8 && mem_eq(name, "win-1251", 8)) || (nl == 11 && mem_eq(name, "windows1251", 11)) ||
                                   (nl == 7 && mem_eq(name, "cp-1251", 7));
                        if (win) {
                            if (!cp1251_to_utf8(src, conv)) return false;
                            src = conv.span();
                        }
                    }
                    break;
                }
            }
        }
    }
    // сохраняем исходник в арене: имена элементов — спаны в нём
    Span owned = intern(src);
    if (src.n && !owned.p) return false;
    if (src.n == 0) return false;

    doc = new_node(XK_DOC);
    if (!doc) return false;
    root = 0;
    Parser P(*this, owned);
    XNode* cur = doc;
    int depth = 0;
    bool seen_root = false;

    // XML-декларация
    if (P.starts("<?xml") && P.pos + 5 < P.s.n && Parser::is_ws(P.s.p[5])) {
        while (!P.eof() && !P.starts("?>")) ++P.pos;
        if (P.eof()) return false;
        P.pos += 2;
    }

    while (!P.eof()) {
        if (P.s.p[P.pos] == '<') {
            if (P.starts("<!--")) {
                size_t b = P.pos + 4, e = b;
                while (e + 3 <= P.s.n && !mem_eq(P.s.p + e, "-->", 3)) ++e;
                if (e + 3 > P.s.n) return false;
                XNode* n = new_node(XK_COMMENT);
                if (!n) return false;
                Bytes tmp;                       // концы строк внутри комментария нормализуем
                for (size_t i = b; i < e; ++i) {
                    if (P.s.p[i] == '\r') { tmp.push('\n'); if (i + 1 < e && P.s.p[i + 1] == '\n') ++i; }
                    else tmp.push(P.s.p[i]);
                }
                n->text = intern(tmp.span());
                append(cur, n);
                P.pos = e + 3;
            } else if (P.starts("<![CDATA[")) {
                if (cur == doc) return false;
                size_t b = P.pos + 9, e = b;
                while (e + 3 <= P.s.n && !mem_eq(P.s.p + e, "]]>", 3)) ++e;
                if (e + 3 > P.s.n) return false;
                XNode* n = new_node(XK_CDATA);
                if (!n) return false;
                Bytes tmp;
                for (size_t i = b; i < e; ++i) {
                    if (P.s.p[i] == '\r') { tmp.push('\n'); if (i + 1 < e && P.s.p[i + 1] == '\n') ++i; }
                    else tmp.push(P.s.p[i]);
                }
                n->text = intern(tmp.span());
                append(cur, n);
                P.pos = e + 3;
            } else if (P.starts("<?")) {
                P.pos += 2;
                Span target = P.read_name();
                if (!target.n) return false;
                P.skip_ws();
                size_t b = P.pos, e = b;
                while (e + 2 <= P.s.n && !mem_eq(P.s.p + e, "?>", 2)) ++e;
                if (e + 2 > P.s.n) return false;
                XNode* n = new_node(XK_PI);
                if (!n) return false;
                n->qname = target;
                n->text = Span(P.s.p + b, e - b);
                append(cur, n);
                P.pos = e + 2;
            } else if (P.starts("<!DOCTYPE")) {
                int br = 0;
                P.pos += 9;
                while (!P.eof()) {
                    u8 c = P.s.p[P.pos++];
                    if (c == '[') ++br;
                    else if (c == ']') --br;
                    else if (c == '>' && br <= 0) break;
                }
            } else if (P.starts("</")) {
                P.pos += 2;
                Span name = P.read_name();
                P.skip_ws();
                if (P.eof() || P.s.p[P.pos] != '>' || cur == doc || !cur->qname.eq(name)) return false;
                ++P.pos;
                cur = cur->parent;
                --depth;
            } else {
                // начальный тег
                if (cur == doc && seen_root) return false;
                ++P.pos;
                Span qname = P.read_name();
                if (!qname.n) return false;
                XNode* e = new_node(XK_ELEM);
                if (!e) return false;
                e->qname = qname;
                struct RawAttr { Span q, v; };
                Vec<RawAttr> raw;
                bool self_close = false;
                for (;;) {
                    P.skip_ws();
                    if (P.eof()) return false;
                    if (P.s.p[P.pos] == '/') {
                        if (P.pos + 1 >= P.s.n || P.s.p[P.pos + 1] != '>') return false;
                        P.pos += 2;
                        self_close = true;
                        break;
                    }
                    if (P.s.p[P.pos] == '>') { ++P.pos; break; }
                    Span an = P.read_name();
                    if (!an.n) return false;
                    P.skip_ws();
                    if (P.eof() || P.s.p[P.pos] != '=') return false;
                    ++P.pos;
                    P.skip_ws();
                    if (P.eof() || (P.s.p[P.pos] != '"' && P.s.p[P.pos] != '\'')) return false;
                    u8 quote = P.s.p[P.pos++];
                    Bytes val;
                    if (!P.read_attr_value(quote, val)) return false;
                    if (raw.n >= 4096) return false;                                         // предел: иначе проверка дубликатов квадратична
                    for (size_t k = 0; k < raw.n; ++k) if (raw.d[k].q.eq(an)) return false;   // дубликат атрибута
                    RawAttr ra;
                    ra.q = an;
                    ra.v = intern(val.span());
                    if (!raw.push(ra)) return false;
                }
                // атрибуты → xmlns-объявления и обычные
                for (size_t k = 0; k < raw.n; ++k) {
                    Span pre, loc;
                    split_qname(raw.d[k].q, pre, loc);
                    if (span_eq_cstr(raw.d[k].q, "xmlns")) {
                        XNs x; x.prefix = Span((const u8*)"", 0); x.uri = raw.d[k].v;
                        e->nsdecls.push(x);
                    } else if (span_eq_cstr(pre, "xmlns")) {
                        if (!loc.n || raw.d[k].v.n == 0) return false;
                        if (e->nsdecls.n >= 512) return false;                              // предел объявлений пространств имён на элемент
                        XNs x; x.prefix = loc; x.uri = raw.d[k].v;
                        e->nsdecls.push(x);
                    }
                }
                append(cur, e);
                Span epre, eloc;
                split_qname(qname, epre, eloc);
                e->prefix = epre; e->local = eloc;
                const Span* u = span_eq_cstr(epre, "xml") ? 0 : lookup_decl(e, epre);
                if (epre.n && !u && !span_eq_cstr(epre, "xml")) return false;      // необъявленный префикс
                e->ns = u ? *u : Span((const u8*)"", 0);
                if (span_eq_cstr(epre, "xml")) e->ns = Span((const u8*)XML_NS, cstrlen(XML_NS));
                for (size_t k = 0; k < raw.n; ++k) {
                    Span pre, loc;
                    split_qname(raw.d[k].q, pre, loc);
                    if (span_eq_cstr(raw.d[k].q, "xmlns") || span_eq_cstr(pre, "xmlns")) continue;
                    XAttr a;
                    a.qname = raw.d[k].q; a.prefix = pre; a.local = loc; a.value = raw.d[k].v;
                    a.ns = Span((const u8*)"", 0);
                    if (pre.n) {
                        if (span_eq_cstr(pre, "xml")) a.ns = Span((const u8*)XML_NS, cstrlen(XML_NS));
                        else {
                            const Span* au = lookup_decl(e, pre);
                            if (!au) return false;
                            a.ns = *au;
                        }
                    }
                    e->attrs.push(a);
                }
                if (cur == doc) { root = e; seen_root = true; }
                if (!self_close) { cur = e; if (++depth > 256) return false; }
            }
        } else {
            Bytes text;
            if (!P.read_text(text)) return false;
            if (cur == doc) {
                for (size_t i = 0; i < text.n; ++i) if (!Parser::is_ws(text.p[i])) return false;
                continue;
            }
            if (text.n == 0) continue;
            if (cur->last && cur->last->kind == XK_TEXT) {
                Bytes merged;
                merged.append(cur->last->text);
                merged.append(text.span());
                cur->last->text = intern(merged.span());
            } else {
                XNode* n = new_node(XK_TEXT);
                if (!n) return false;
                n->text = intern(text.span());
                append(cur, n);
            }
        }
    }
    return cur == doc && root != 0;
}

// ---- экранирование --------------------------------------------------------------------------

bool xml_escape_text(Span in, Bytes& out) {
    for (size_t i = 0; i < in.n; ++i) {
        u8 c = in.p[i];
        bool ok = true;
        switch (c) {
            case '&': ok = out.append_str("&amp;"); break;
            case '<': ok = out.append_str("&lt;"); break;
            case '>': ok = out.append_str("&gt;"); break;
            case '\r': ok = out.append_str("&#13;"); break;
            default: ok = out.push(c);
        }
        if (!ok) return false;
    }
    return true;
}

bool xml_escape_attr(Span in, Bytes& out) {
    for (size_t i = 0; i < in.n; ++i) {
        u8 c = in.p[i];
        bool ok = true;
        switch (c) {
            case '&': ok = out.append_str("&amp;"); break;
            case '<': ok = out.append_str("&lt;"); break;
            case '>': ok = out.append_str("&gt;"); break;
            case '"': ok = out.append_str("&quot;"); break;
            case '\n': ok = out.append_str("&#10;"); break;
            case '\r': ok = out.append_str("&#13;"); break;
            case '\t': ok = out.append_str("&#9;"); break;
            default: ok = out.push(c);
        }
        if (!ok) return false;
    }
    return true;
}

// ---- сериализация (как libxml2) ------------------------------------------------------------------

static bool ser_node(const XNode* n, Bytes& out, const XNode* ins, Span raw) {
    switch (n->kind) {
        case XK_TEXT: return xml_escape_text(n->text, out);
        case XK_CDATA: return out.append_str("<![CDATA[") && out.append(n->text) && out.append_str("]]>");
        case XK_COMMENT: return out.append_str("<!--") && out.append(n->text) && out.append_str("-->");
        case XK_PI:
            if (!out.append_str("<?") || !out.append(n->qname)) return false;
            if (n->text.n && (!out.push(' ') || !out.append(n->text))) return false;
            return out.append_str("?>");
        case XK_ELEM: {
            if (!out.push('<') || !out.append(n->qname)) return false;
            for (size_t i = 0; i < n->nsdecls.n; ++i) {
                const XNs& x = n->nsdecls.d[i];
                if (!out.append_str(" xmlns")) return false;
                if (x.prefix.n && (!out.push(':') || !out.append(x.prefix))) return false;
                if (!out.append_str("=\"") || !xml_escape_attr(x.uri, out) || !out.push('"')) return false;
            }
            for (size_t i = 0; i < n->attrs.n; ++i) {
                const XAttr& a = n->attrs.d[i];
                if (!out.push(' ') || !out.append(a.qname) || !out.append_str("=\"") || !xml_escape_attr(a.value, out) || !out.push('"')) return false;
            }
            bool insert_here = (ins == n);
            if (!n->first && !insert_here) return out.append_str("/>");
            if (!out.push('>')) return false;
            for (const XNode* c = n->first; c; c = c->next)
                if (!ser_node(c, out, ins, raw)) return false;
            if (insert_here && !out.append(raw)) return false;
            return out.append_str("</") && out.append(n->qname) && out.push('>');
        }
        default: return true;
    }
}

bool xml_serialize(const XDoc& d, Bytes& out, const XNode* ins, Span raw) {
    if (!out.append_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")) return false;
    for (const XNode* c = d.doc->first; c; c = c->next) {
        if (!ser_node(c, out, ins, raw) || !out.push('\n')) return false;
    }
    return true;
}

// ---- C14N -----------------------------------------------------------------------------------------------

namespace {

struct C14n {
    const C14nOptions& opt;
    XSkipFn skip;
    void* sctx;
    Bytes& out;
    const XNode* apex;
    C14n(const C14nOptions& o, XSkipFn s, void* c, Bytes& b, const XNode* a) : opt(o), skip(s), sctx(c), out(b), apex(a) {}
};

bool esc_c14n_text(Span in, Bytes& out) {
    for (size_t i = 0; i < in.n; ++i) {
        u8 c = in.p[i];
        bool ok;
        if (c == '&') ok = out.append_str("&amp;");
        else if (c == '<') ok = out.append_str("&lt;");
        else if (c == '>') ok = out.append_str("&gt;");
        else if (c == '\r') ok = out.append_str("&#xD;");
        else ok = out.push(c);
        if (!ok) return false;
    }
    return true;
}

bool esc_c14n_attr(Span in, Bytes& out) {
    for (size_t i = 0; i < in.n; ++i) {
        u8 c = in.p[i];
        bool ok;
        if (c == '&') ok = out.append_str("&amp;");
        else if (c == '<') ok = out.append_str("&lt;");
        else if (c == '"') ok = out.append_str("&quot;");
        else if (c == '\t') ok = out.append_str("&#x9;");
        else if (c == '\n') ok = out.append_str("&#xA;");
        else if (c == '\r') ok = out.append_str("&#xD;");
        else ok = out.push(c);
        if (!ok) return false;
    }
    return true;
}

int span_cmp(Span a, Span b) {
    size_t m = a.n < b.n ? a.n : b.n;
    int c = memcmp(a.p, b.p, m);
    if (c) return c;
    return a.n < b.n ? -1 : (a.n > b.n ? 1 : 0);
}

bool rendered_get(const Vec<XNs>& r, Span prefix, Span& uri) {
    for (size_t i = 0; i < r.n; ++i)
        if (r.d[i].prefix.eq(prefix)) { uri = r.d[i].uri; return true; }
    return false;
}

void rendered_set(Vec<XNs>& r, Span prefix, Span uri) {
    for (size_t i = 0; i < r.n; ++i)
        if (r.d[i].prefix.eq(prefix)) { r.d[i].uri = uri; return; }
    XNs x; x.prefix = prefix; x.uri = uri;
    r.push(x);
}

// пространства имён в области видимости элемента: ближайшее объявление побеждает
void collect_scope(const XNode* e, Vec<XNs>& scope) {
    for (const XNode* n = e; n; n = n->parent) {
        for (size_t i = 0; i < n->nsdecls.n; ++i) {
            bool seen = false;
            for (size_t k = 0; k < scope.n; ++k) if (scope.d[k].prefix.eq(n->nsdecls.d[i].prefix)) seen = true;
            if (!seen) scope.push(n->nsdecls.d[i]);
        }
    }
}

bool lookup_scope(const Vec<XNs>& scope, Span prefix, Span& uri) {
    for (size_t i = 0; i < scope.n; ++i)
        if (scope.d[i].prefix.eq(prefix)) { uri = scope.d[i].uri; return true; }
    return false;
}

struct AttrOut { Span ns, local, qname, value; };

bool c14n_elem(C14n& c, const XNode* e, const Vec<XNs>& R);

bool c14n_children(C14n& c, const XNode* parent, const Vec<XNs>& R) {
    for (const XNode* n = parent->first; n; n = n->next) {
        if (c.skip && c.skip(n, c.sctx)) continue;
        switch (n->kind) {
            case XK_TEXT: case XK_CDATA:
                if (!esc_c14n_text(n->text, c.out)) return false;
                break;
            case XK_COMMENT:
                if (c.opt.comments && !(c.out.append_str("<!--") && c.out.append(n->text) && c.out.append_str("-->"))) return false;
                break;
            case XK_PI:
                if (!c.out.append_str("<?") || !c.out.append(n->qname)) return false;
                if (n->text.n && (!c.out.push(' ') || !c.out.append(n->text))) return false;
                if (!c.out.append_str("?>")) return false;
                break;
            case XK_ELEM:
                if (!c14n_elem(c, n, R)) return false;
                break;
            default: break;
        }
    }
    return true;
}

bool c14n_elem(C14n& c, const XNode* e, const Vec<XNs>& R) {
    if (c.skip && c.skip(e, c.sctx)) return true;
    Vec<XNs> scope;
    collect_scope(e, scope);
    Vec<XNs> emit;
    if (!c.opt.exclusive) {
        for (size_t i = 0; i < scope.n; ++i) {
            Span p = scope.d[i].prefix, u = scope.d[i].uri, cur;
            if (!rendered_get(R, p, cur)) cur = Span((const u8*)"", 0);
            if (!cur.eq(u)) emit.push(scope.d[i]);
        }
    } else {
        Vec<Span> used;
        used.push(e->prefix);
        for (size_t i = 0; i < e->attrs.n; ++i)
            if (e->attrs.d[i].prefix.n && !span_eq_cstr(e->attrs.d[i].prefix, "xml")) {
                bool dup = false;
                for (size_t k = 0; k < used.n; ++k) if (used.d[k].eq(e->attrs.d[i].prefix)) dup = true;
                if (!dup) used.push(e->attrs.d[i].prefix);
            }
        for (size_t i = 0; i < c.opt.incl_n; ++i) {
            bool dup = false;
            for (size_t k = 0; k < used.n; ++k) if (used.d[k].eq(c.opt.incl_prefixes[i])) dup = true;
            if (!dup) used.push(c.opt.incl_prefixes[i]);
        }
        for (size_t i = 0; i < used.n; ++i) {
            Span p = used.d[i], u;
            bool found = lookup_scope(scope, p, u);
            if (p.n && !found) continue;
            if (!found) u = Span((const u8*)"", 0);
            Span cur;
            if (!rendered_get(R, p, cur)) cur = Span((const u8*)"", 0);
            if (!cur.eq(u)) { XNs x; x.prefix = p; x.uri = u; emit.push(x); }
        }
    }
    for (size_t i = 0; i < emit.n; ++i)
        for (size_t j = i + 1; j < emit.n; ++j)
            if (span_cmp(emit.d[j].prefix, emit.d[i].prefix) < 0) { XNs t = emit.d[i]; emit.d[i] = emit.d[j]; emit.d[j] = t; }

    Vec<XNs> R2;
    for (size_t i = 0; i < R.n; ++i) R2.push(R.d[i]);
    for (size_t i = 0; i < emit.n; ++i) rendered_set(R2, emit.d[i].prefix, emit.d[i].uri);

    if (!c.out.push('<') || !c.out.append(e->qname)) return false;
    for (size_t i = 0; i < emit.n; ++i) {
        if (!c.out.append_str(" xmlns")) return false;
        if (emit.d[i].prefix.n && (!c.out.push(':') || !c.out.append(emit.d[i].prefix))) return false;
        if (!c.out.append_str("=\"") || !esc_c14n_attr(emit.d[i].uri, c.out) || !c.out.push('"')) return false;
    }
    // атрибуты
    Vec<AttrOut> attrs;
    for (size_t i = 0; i < e->attrs.n; ++i) {
        AttrOut a; a.ns = e->attrs.d[i].ns; a.local = e->attrs.d[i].local; a.qname = e->attrs.d[i].qname; a.value = e->attrs.d[i].value;
        attrs.push(a);
    }
    if (e == c.apex && e->parent && e->parent->kind != XK_DOC && !c.opt.exclusive) {
        // наследование xml:* от предков (C14N 1.0; в 1.1 — только lang/space)
        for (const XNode* a = e->parent; a && a->kind == XK_ELEM; a = a->parent) {
            for (size_t i = 0; i < a->attrs.n; ++i) {
                const XAttr& x = a->attrs.d[i];
                if (!span_eq_cstr(x.ns, XML_NS)) continue;
                if (c.opt.v11 && !span_eq_cstr(x.local, "lang") && !span_eq_cstr(x.local, "space")) continue;
                bool have = false;
                for (size_t k = 0; k < attrs.n; ++k) if (attrs.d[k].ns.eq(x.ns) && attrs.d[k].local.eq(x.local)) have = true;
                if (!have) { AttrOut o; o.ns = x.ns; o.local = x.local; o.qname = x.qname; o.value = x.value; attrs.push(o); }
            }
        }
    }
    for (size_t i = 0; i < attrs.n; ++i)
        for (size_t j = i + 1; j < attrs.n; ++j) {
            int cmp = span_cmp(attrs.d[j].ns, attrs.d[i].ns);
            if (cmp == 0) cmp = span_cmp(attrs.d[j].local, attrs.d[i].local);
            if (cmp < 0) { AttrOut t = attrs.d[i]; attrs.d[i] = attrs.d[j]; attrs.d[j] = t; }
        }
    for (size_t i = 0; i < attrs.n; ++i) {
        if (!c.out.push(' ') || !c.out.append(attrs.d[i].qname) || !c.out.append_str("=\"") ||
            !esc_c14n_attr(attrs.d[i].value, c.out) || !c.out.push('"')) return false;
    }
    if (!c.out.push('>')) return false;
    if (!c14n_children(c, e, R2)) return false;
    return c.out.append_str("</") && c.out.append(e->qname) && c.out.push('>');
}

}  // namespace

bool xml_c14n(const XNode* apex, XSkipFn skip, void* ctx, const C14nOptions& opt, Bytes& out) {
    C14n c(opt, skip, ctx, out, apex);
    Vec<XNs> R;
    if (apex->kind == XK_ELEM) return c14n_elem(c, apex, R);
    // документ целиком: комментарии и PI верхнего уровня отделяются переводами строки
    bool after_root = false;
    for (const XNode* n = apex->first; n; n = n->next) {
        if (skip && skip(n, ctx)) continue;
        if (n->kind == XK_ELEM) {
            if (!c14n_elem(c, n, R)) return false;
            after_root = true;
        } else if (n->kind == XK_COMMENT) {
            if (!opt.comments) continue;
            if (after_root && !out.push('\n')) return false;
            if (!out.append_str("<!--") || !out.append(n->text) || !out.append_str("-->")) return false;
            if (!after_root && !out.push('\n')) return false;
        } else if (n->kind == XK_PI) {
            if (after_root && !out.push('\n')) return false;
            if (!out.append_str("<?") || !out.append(n->qname)) return false;
            if (n->text.n && (!out.push(' ') || !out.append(n->text))) return false;
            if (!out.append_str("?>")) return false;
            if (!after_root && !out.push('\n')) return false;
        }
    }
    return true;
}

}  // namespace nek
