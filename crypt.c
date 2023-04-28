/* CC-BY license applied, see LICENCE.md */

#include <stdlib.h>
#include <string.h>
#include <assert.h>

/*
 * We use the standard POSIX crypt, when we can.  On Windows, we need
 * some other library function like...  Oh, OpenSSL's DES_crypt()!
 *
 * CMakeLists.txt must ensure that the correct library is linked.
 * -lcrypt on Unix and MacOS, libcrypto.lib on Windows.
 */
#if defined(_MSC_VER)
# define OPENSSL_SUPPRESS_DEPRECATED
# include <openssl/des.h>
# define crypt(p,s) (DES_crypt((p),(s)))
#elif defined(__APPLE__)
# include <unistd.h>
#else
# include <crypt.h>
#endif

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/err.h>

#include "prov/err.h"
#include "prov/num.h"

#include "e_params.h"
#include "local.h"
#include "crypt_data.h"

/*
 * Forward declarations to ensure we get signatures right.  All the
 * OSSL_FUNC_* types come from <openssl/core_dispatch.h>
 */
static OSSL_FUNC_kdf_newctx_fn crypt_newctx;
static OSSL_FUNC_kdf_freectx_fn crypt_freectx;
static OSSL_FUNC_kdf_dupctx_fn crypt_dupctx;

static OSSL_FUNC_kdf_reset_fn crypt_reset;
static OSSL_FUNC_kdf_derive_fn crypt_derive;
static OSSL_FUNC_kdf_get_params_fn crypt_get_params;
static OSSL_FUNC_kdf_gettable_params_fn crypt_gettable_params;
static OSSL_FUNC_kdf_set_ctx_params_fn crypt_set_ctx_params;
static OSSL_FUNC_kdf_get_ctx_params_fn crypt_get_ctx_params;
static OSSL_FUNC_kdf_settable_ctx_params_fn crypt_settable_ctx_params;
static OSSL_FUNC_kdf_gettable_ctx_params_fn crypt_gettable_ctx_params;

/*
 * The context used throughout all these functions.
 */
struct crypt_ctx_st {
    struct provider_ctx_st *provctx;

#define RESULTING_KEYLENGTH 13
    char *pass;                 /* A copy of the password */
    char *salt;                 /* 2 byte salt */
};
#define ERR_HANDLE(ctx) ((ctx)->provctx->proverr_handle)

static void *crypt_newctx(void *vprovctx)
{
    struct crypt_ctx_st *ctx = malloc(sizeof(*ctx));

    if (ctx != NULL) {
        memset(ctx, 0, sizeof(*ctx));
        ctx->provctx = vprovctx;
    }
    return ctx;
}

static void crypt_freectx(void *vctx)
{
    struct crypt_ctx_st *ctx = vctx;

    ctx->provctx = NULL;
    crypt_reset(ctx);
    free(ctx);
}

static void *crypt_dupctx(void *vctx)
{
    struct crypt_ctx_st *src = vctx;
    struct crypt_ctx_st *dst = NULL;

    if (src == NULL
        || (dst = crypt_newctx(NULL)) == NULL)

    dst->provctx = src->provctx;
    dst->provctx->proverr_handle =
        proverr_dup_handle(src->provctx->proverr_handle);

    if (src->pass != NULL) {
        if ((dst->pass = strdup(src->pass)) == NULL) {
            crypt_freectx(dst);
            return NULL;
        }
    }
    if (src->salt != NULL) {
        if ((dst->salt = strdup(src->salt)) == NULL) {
            crypt_freectx(dst);
            return NULL;
        }
    }

    return dst;
}

static void crypt_reset(void *vctx)
{
    struct crypt_ctx_st *ctx = vctx;

    if (ctx == NULL)
        return;
    free(ctx->pass);
    ctx->pass = NULL;
    free(ctx->salt);
    ctx->salt = NULL;
}

static int crypt_derive(void *vctx, unsigned char *key, size_t keylen,
                        const OSSL_PARAM params[])
{
    struct crypt_ctx_st *ctx = vctx;
    char *result = NULL;
    size_t result_len = 0;

    if (params != NULL
        && !crypt_set_ctx_params(ctx, params))
        return 0;

    if ((result = crypt(ctx->pass, ctx->salt)) == NULL) {
        ERR_raise(ERR_HANDLE(ctx), EXTRA_E_CRYPT_DERIVE_FAILED);
        return 0;
    }

    /*
     * All possible results are fixed size... we hope.  The KDF interface
     * makes it hard to have variable size results.
     */
    result_len = strlen(result);
    if (keylen != result_len) {
        ERR_raise(ERR_HANDLE(ctx), EXTRA_E_INVALID_KEYLEN);
        return 0;
    }

    memcpy(key, result, keylen);
    return 1;
}

/* Parameters that libcrypto can get from this implementation */
static const OSSL_PARAM *crypt_gettable_params(void *provctx)
{
    static const OSSL_PARAM table[] = {
        { S_PARAM_size, OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0 },
        { NULL, 0, NULL, 0, 0 },
    };

    return table;
}

static int crypt_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    int ok = 1;

    for (p = params; p->key != NULL; p++)
        switch (extra_params_parse(p->key)) {
        case V_PARAM_size:
            ok &= (provnum_set_size_t(p, RESULTING_KEYLENGTH + 1) >= 0);
            break;
        }
    return ok;
}

/* Parameters that libcrypto can send to this implementation */
static const OSSL_PARAM *crypt_settable_ctx_params(void *cctx, void *provctx)
{
    static const OSSL_PARAM table[] = {
        { S_PARAM_pass, OSSL_PARAM_UTF8_STRING, NULL, 0, 0 },
        { S_PARAM_salt, OSSL_PARAM_UTF8_STRING, NULL, 0, 0 },
        { NULL, 0, NULL, 0, 0 },
    };

    return table;
}

static int crypt_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    struct crypt_ctx_st *ctx = vctx;
    const OSSL_PARAM *p;
    int ok = 1;

    for (p = params; p->key != NULL; p++)
        switch (extra_params_parse(p->key)) {
        case V_PARAM_pass:
        {
            char *newpass = strndup(p->data, p->data_size);

            if (newpass == NULL) {
                ERR_raise(ERR_HANDLE(ctx), ERR_R_MALLOC_FAILURE);
                ok = 0;
            } else {
                free(ctx->pass);
                ctx->pass = newpass;
            }
            break;
        }
        case V_PARAM_salt:
        {
            char *newsalt;

            if (p->data_size < 2) {
                ERR_raise(ERR_HANDLE(ctx), EXTRA_E_CRYPT_SALT_TOO_SMALL);
                ok = 0;
            } else if ((newsalt = strndup(p->data, p->data_size)) == NULL) {
                ERR_raise(ERR_HANDLE(ctx), ERR_R_MALLOC_FAILURE);
                ok = 0;
            } else {
                free(ctx->salt);
                ctx->salt = newsalt;
            }
            break;
        }
        }
    return ok;
}

/* The Crypt dispatch table */
const OSSL_DISPATCH crypt_functions[] = {
    { OSSL_FUNC_KDF_NEWCTX, (funcptr_t)crypt_newctx },
    { OSSL_FUNC_KDF_FREECTX, (funcptr_t)crypt_freectx },
    { OSSL_FUNC_KDF_DUPCTX, (funcptr_t)crypt_dupctx },
    { OSSL_FUNC_KDF_DERIVE, (funcptr_t)crypt_derive },
    { OSSL_FUNC_KDF_GET_PARAMS, (funcptr_t)crypt_get_params },
    { OSSL_FUNC_KDF_GETTABLE_PARAMS, (funcptr_t)crypt_gettable_params },
    { OSSL_FUNC_KDF_SET_CTX_PARAMS, (funcptr_t)crypt_set_ctx_params },
    { OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS,
      (funcptr_t)crypt_settable_ctx_params },
    { 0, NULL }
};

