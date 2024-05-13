// SPDX-FileCopyrightText: 2022-2024 "extra" provider collective
//
// SPDX-License-Identifier: LGPL-3.0-or-later

/* CC-BY license applied, see LICENCE.md */

#include <stdlib.h>
#include <openssl/core.h>

#ifndef LOCAL_H
# define LOCAL_H

/* The global error reasons used here */
# define EXTRA_E_INVALID_KEYLEN                1
# define EXTRA_E_INVALID_INPUT_LENGTH          2
# define EXTRA_E_OUTPUT_SIZE_TOO_SMALL         3
# define EXTRA_E_HARD_CODED_VALUE              4
# define EXTRA_E_INVALID_OUTPUT_SIZE           5

# define GLOBAL_EXTRA_REASONS                                           \
    { EXTRA_E_INVALID_KEYLEN, "Invalid key length" },                   \
    { EXTRA_E_INVALID_INPUT_LENGTH, "invalid input length" },           \
    { EXTRA_E_OUTPUT_SIZE_TOO_SMALL, "output size is too small" },      \
    { EXTRA_E_HARD_CODED_VALUE, "value is hard coded, may not be changed" }, \
    { EXTRA_E_INVALID_OUTPUT_SIZE, "invalid output size" }

struct provider_ctx_st {
    const OSSL_CORE_HANDLE *core_handle;
    struct proverr_functions_st *proverr_handle;
};

typedef void (*funcptr_t)(void);

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
