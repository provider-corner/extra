/* CC-BY license applied, see LICENCE.md */

#include <stdlib.h>
#include <openssl/core.h>

#ifndef LOCAL_H
# define LOCAL_H

/* The error reasons used here */
# define EXTRA_E_INVALID_KEYLEN                1
# define EXTRA_E_CRYPT_DERIVE_FAILED           2
# define EXTRA_E_CRYPT_SALT_TOO_SMALL          3

struct provider_ctx_st {
    const OSSL_CORE_HANDLE *core_handle;
    struct proverr_functions_st *proverr_handle;
};

typedef void (*funcptr_t)(void);
extern const OSSL_DISPATCH crypt_functions[];

/* Windows fixups */
# if defined(_MSC_VER)
#  define strcasecmp _stricmp
#  define strdup _strdup

static inline char *strndup(char *str, size_t chars)
{
    char *buf;

    buf = malloc(chars + 1);
    if (buf != NULL) {
        buf[chars] = '\0';
        strncpy(buf, str, chars);
    }
    return buf;
}
# endif

#endif
