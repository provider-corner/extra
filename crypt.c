/* CC-BY license applied, see LICENCE.md */

#include <stdlib.h>
#include <string.h>
#include <assert.h>

/*
 * We're calling DES_fcrypt(). which is deprecated.
 * Defining this macro suppresses the deprecation warning.
 * NOTE: This will NOT build well with a libcrypto that has been
 * configured with 'no-deprecated'.  Don't even try!
 */
#define OPENSSL_SUPPRESS_DEPRECATED

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/des.h>
#include <openssl/err.h>

#include "prov/err.h"
#include "prov/num.h"

#include "local.h"

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

    dst->provctx->proverr_handle =
        proverr_dup_handle(src->provctx->proverr_handle);
    dst->provctx = src->provctx;

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
    unsigned char buff[RESULTING_KEYLENGTH + 1];

    if (params != NULL
        && !crypt_set_ctx_params(ctx, params))
        return 0;

    if (keylen != RESULTING_KEYLENGTH) {
        ERR_raise(ERR_HANDLE(ctx), EXTRA_E_INVALID_KEYLEN);
        return 0;
    }

    if (DES_fcrypt(ctx->pass, ctx->salt, buff) == NULL) {
        ERR_raise(ERR_HANDLE(ctx), EXTRA_E_CRYPT_DERIVE_FAILED);
        return 0;
    }
    memcpy(key, buff, keylen);
    return 1;
}

/* Parameters that libcrypto can get from this implementation */
static const OSSL_PARAM *crypt_gettable_params(void *provctx)
{
    static const OSSL_PARAM table[] = {
        { "size", OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0 },
        { NULL, 0, NULL, 0, 0 },
    };

    return table;
}

static int crypt_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    int ok = 1;

    for (p = params; p->key != NULL; p++) {
        if (strcasecmp(p->key, "size") == 0)
            if (provnum_set_size_t(p, RESULTING_KEYLENGTH + 1) < 0) {
                ok = 0;
                continue;
            }
    }
    return ok;
}

/* Parameters that libcrypto can send to this implementation */
static const OSSL_PARAM *crypt_settable_ctx_params(void *cctx, void *provctx)
{
    static const OSSL_PARAM table[] = {
        { "pass", OSSL_PARAM_UTF8_STRING, NULL, sizeof(size_t), 0 },
        { "salt", OSSL_PARAM_UTF8_STRING, NULL, sizeof(size_t), 0 },
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
        if (strcasecmp(p->key, "pass") == 0) {
            char *newpass = strndup(p->data, p->data_size);

            if (newpass == NULL) {
                ERR_raise(ERR_HANDLE(ctx), ERR_R_MALLOC_FAILURE);
                ok = 0;
                continue;
            }

            free(ctx->pass);
            ctx->pass = newpass;
        } else if (strcasecmp(p->key, "salt") == 0) {
            char *newsalt = strndup(p->data, p->data_size);

            if (newsalt == NULL) {
                ERR_raise(ERR_HANDLE(ctx), ERR_R_MALLOC_FAILURE);
                ok = 0;
                continue;
            }

            free(ctx->salt);
            ctx->salt = newsalt;
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

