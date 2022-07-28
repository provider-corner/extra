/* CC-BY license applied, see LICENCE.md */

#include <openssl/core.h>

/* The error reasons used here */
#define EXTRA_E_INVALID_KEYLEN         1
#define EXTRA_E_CRYPT_DERIVE_FAILED    2
#define EXTRA_E_CRYPT_SALT_TOO_SMALL   3

struct provider_ctx_st {
    const OSSL_CORE_HANDLE *core_handle;
    struct proverr_functions_st *proverr_handle;
};

typedef void (*funcptr_t)(void);
extern const OSSL_DISPATCH crypt_functions[];
