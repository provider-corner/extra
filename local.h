/* CC-BY license applied, see LICENCE.md */

#include <stdlib.h>
#include <openssl/core.h>

#ifndef LOCAL_H
# define LOCAL_H

/* The error reasons used here */
# define EXTRA_E_INVALID_KEYLEN                1
# define EXTRA_E_CRYPT_DERIVE_FAILED           2
# define EXTRA_E_CRYPT_SALT_TOO_SMALL          3
# define EXTRA_E_INVALID_INPUT_LENGTH          4
# define EXTRA_E_OUTPUT_SIZE_TOO_SMALL         5
# define EXTRA_E_HARD_CODED_VALUE              6
/* The following errors mimic the ones in external/md6/md6.h */
# define EXTRA_E_MD6__BASE                   100
# define EXTRA_E_MD6_FAIL                    101
# define EXTRA_E_MD6_BADHASHLEN              102
# define EXTRA_E_MD6_NULLSTATE               103
# define EXTRA_E_MD6_BADKEYLEN               104
# define EXTRA_E_MD6_STATENOTINIT            105
# define EXTRA_E_MD6_STACKUNDERFLOW          106
# define EXTRA_E_MD6_STACKOVERFLOW           107
# define EXTRA_E_MD6_NULLDATA                108
# define EXTRA_E_MD6_NULL_N                  109
# define EXTRA_E_MD6_NULL_B                  110
# define EXTRA_E_MD6_BAD_ELL                 111
# define EXTRA_E_MD6_BAD_p                   112
# define EXTRA_E_MD6_NULL_K                  113
# define EXTRA_E_MD6_NULL_Q                  114
# define EXTRA_E_MD6_NULL_C                  115
# define EXTRA_E_MD6_BAD_L                   116
# define EXTRA_E_MD6_BAD_r                   117
# define EXTRA_E_MD6_OUT_OF_MEMORY           118

struct provider_ctx_st {
    const OSSL_CORE_HANDLE *core_handle;
    struct proverr_functions_st *proverr_handle;
};

typedef void (*funcptr_t)(void);
extern const OSSL_DISPATCH crypt_functions[];
extern const OSSL_DISPATCH o_md6_functions[];
extern const OSSL_DISPATCH o_md6_224_functions[];
extern const OSSL_DISPATCH o_md6_256_functions[];
extern const OSSL_DISPATCH o_md6_384_functions[];
extern const OSSL_DISPATCH o_md6_512_functions[];

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
