/* CC-BY license applied, see LICENCE.md */

extern const OSSL_DISPATCH crypt_functions[];

#define CRYPT_AUTHOR "@levitte"
#define CRYPT_ALGORITHMS(globalprops)                                   \
  { "crypt", globalprops ",x.author='" CRYPT_AUTHOR "'", crypt_functions }

#define EXTRA_E_CRYPT__BASE                  100
#define EXTRA_E_CRYPT_DERIVE_FAILED          101
#define EXTRA_E_CRYPT_SALT_TOO_SMALL         102

#define CRYPT_REASONS                           \
    { EXTRA_E_CRYPT_DERIVE_FAILED, "key derivation failed" },   \
    { EXTRA_E_CRYPT_SALT_TOO_SMALL, "salt is to small" }
