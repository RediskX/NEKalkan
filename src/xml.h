// NEKalkan — минимальный XML: разбор с пространствами имён, каноникализация (C14N 1.0/1.1, Exclusive), сериализация.
#pragma once
#include "rt.h"
#include "codec.h"

namespace nek {

enum XKind { XK_DOC, XK_ELEM, XK_TEXT, XK_CDATA, XK_COMMENT, XK_PI };

struct XAttr {
    Span qname, prefix, local, value, ns;     // value — декодированное значение
};
struct XNs {
    Span prefix, uri;                         // prefix пуст для xmlns="…"
};

struct XNode {
    XKind kind = XK_ELEM;
    XNode *parent = 0, *first = 0, *last = 0, *next = 0, *prev = 0;
    Span qname, prefix, local, ns;            // элемент; для PI qname = цель
    Span text;                                // TEXT/CDATA/COMMENT — содержимое; PI — данные
    Vec<XAttr> attrs;                         // без xmlns-объявлений
    Vec<XNs> nsdecls;                         // объявления пространств имён на этом элементе

    const XAttr* attr(const char* qname) const;
    const XAttr* attr_local(const char* local) const;   // первый атрибут с таким локальным именем (без пространства)
};

extern const char* const XML_NS;              // http://www.w3.org/XML/1998/namespace
extern const char* const DS_NS;               // http://www.w3.org/2000/09/xmldsig#

class XDoc {
public:
    XNode* doc = 0;                           // XK_DOC: дети — комментарии/PI верхнего уровня и корневой элемент
    XNode* root = 0;
    Vec<XNode*> all;
    Vec<Bytes*> chunks;
    size_t chunk_used = 0;

    ~XDoc();
    // Разбор. Вход — UTF-8 (BOM допускается), UTF-16 с BOM или CP1251 при объявленной кодировке.
    // assume_utf8 — вход уже UTF-8 (строка из 1С): объявленная в декларации кодировка игнорируется.
    bool parse(Span in, bool assume_utf8 = false);

    XNode* new_node(XKind k);
    Span intern(Span s);
    void append(XNode* parent, XNode* child);

    // Поиск элемента по локальному имени и пространству имён (пустое ns = «без пространства»); первый в порядке документа.
    const XNode* find_element(const XNode* from, Span local, Span ns) const;
    // Поиск элемента по значению атрибута Id/ID (как xmlsec)
    const XNode* find_by_id(Span id) const;
    // Есть ли в документе хотя бы один элемент с таким Id/ID
    bool id_exists(Span id) const;
};

struct C14nOptions {
    bool exclusive = false;
    bool comments = false;
    bool v11 = false;
    const Span* incl_prefixes = 0;            // InclusiveNamespaces PrefixList («#default» — пустой префикс)
    size_t incl_n = 0;
};

// skip(node) == true — узел и поддерево исключаются из набора узлов.
typedef bool (*XSkipFn)(const XNode*, void*);

// apex — XK_DOC (весь документ) либо элемент (его поддерево).
bool xml_c14n(const XNode* apex, XSkipFn skip, void* ctx, const C14nOptions& opt, Bytes& out);

// Сериализация «как libxml2 (xmlDocDumpMemory)»: <?xml version="1.0" encoding="UTF-8"?>\n …
// insert_parent/raw_insert — необязательная вставка готового XML в конец содержимого указанного элемента.
bool xml_serialize(const XDoc& d, Bytes& out, const XNode* insert_parent = 0, Span raw_insert = Span());

// Экранирование значений для записи в XML
bool xml_escape_text(Span in, Bytes& out);
bool xml_escape_attr(Span in, Bytes& out);

}  // namespace nek
