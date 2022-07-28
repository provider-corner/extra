/* CC-BY license applied, see LICENCE.md */

#include <openssl/core.h>

struct provider_ctx_st {
    const OSSL_CORE_HANDLE *core_handle;
    struct proverr_functions_st *proverr_handle;
};

typedef void (*funcptr_t)(void);
