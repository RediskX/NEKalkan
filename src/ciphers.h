// NEKalkan — блочные шифры для чтения контейнеров PKCS#12: DES/3DES, RC2, AES (только расшифрование, CBC).
#pragma once
#include "rt.h"

namespace nek {

// 3DES-EDE (ключ 24 байта; для DES — 8 байт и des_cbc_decrypt). Длина данных кратна 8.
bool des3_cbc_decrypt(Span key24, Span iv8, Span in, u8* out);
bool des_cbc_decrypt(Span key8, Span iv8, Span in, u8* out);
// RC2-CBC; effective_bits — эффективная длина ключа (для pbeWithSHAAnd40BitRC2-CBC — 40).
bool rc2_cbc_decrypt(Span key, int effective_bits, Span iv8, Span in, u8* out);
// AES-CBC (ключ 16/24/32 байта). Длина данных кратна 16.
bool aes_cbc_decrypt(Span key, Span iv16, Span in, u8* out);

// Снять PKCS#7-дополнение; false, если оно некорректно.
bool pkcs7_unpad(Bytes& b, size_t block);

}  // namespace nek
