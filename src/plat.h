// NEKalkan — тонкий слой над ОС (память, файлы, время, случайные числа).
#pragma once
#include "rt.h"

namespace nek {

void* plat_alloc(size_t n);
void* plat_realloc(void* p, size_t n);
void plat_free(void* p);
long plat_live_allocs();                                // число живых блоков (только в сборке -Guard, иначе -1) — для проверки утечек в тестах

bool plat_random(void* buf, size_t n);                  // криптографически стойкий ГСЧ ОС
i64 plat_unix_time();                                   // секунды от 1970-01-01 UTC
i64 plat_local_offset(i64 unix_utc);                     // смещение местного времени от UTC на этот момент, секунды

// Пути — в UTF-8.
bool plat_read_file(const char* path_utf8, Bytes& out);
bool plat_write_file(const char* path_utf8, Span data);
bool plat_file_exists(const char* path_utf8);

void plat_debug(const char* msg);                       // OutputDebugString

// Системная ANSI-кодовая страница (CP_ACP) <-> UTF-16. false — символ не представим / ошибка.
bool plat_acp_from_wide(const u16* w, size_t n, Bytes& out);
bool plat_acp_to_wide(Span in, Vec<u16>& out);

}  // namespace nek
