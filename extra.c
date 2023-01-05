/* CC-BY license applied, see LICENCE.md */

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <openssl/core.h>
#include <openssl/core_dispatch.h>

#include "prov/err.h"
#include "prov/num.h"

#include "local.h"

/*********************************************************************
 *
 *  Errors
 *
 *****/

static const OSSL_ITEM reason_strings[] = {
    { EXTRA_E_INVALID_KEYLEN, "Invalid key length" },
    { EXTRA_E_CRYPT_DERIVE_FAILED, "key derivation failed" },
    { EXTRA_E_CRYPT_SALT_TOO_SMALL, "salt is to small" },
    { EXTRA_E_INVALID_INPUT_LENGTH, "invalid input length" },
    { EXTRA_E_OUTPUT_SIZE_TOO_SMALL, "output size is too small" },
    { EXTRA_E_HARD_CODED_VALUE, "value is hard coded, may not be changed" },

    /* The following errors mimic the ones in external/md6/md6.h */
    { EXTRA_E_MD6_FAIL,                 "generic md6 failure" },
    { EXTRA_E_MD6_BADHASHLEN,           "bad md6 hash length (allowed values are 1 to 512)" },
    { EXTRA_E_MD6_NULLSTATE,            "null md6 state" },
    { EXTRA_E_MD6_BADKEYLEN,            "bad md6 key length" },
    { EXTRA_E_MD6_STATENOTINIT,         "md6 state not initialized" },
    { EXTRA_E_MD6_STACKUNDERFLOW,       "md6 stack underflows" },
    { EXTRA_E_MD6_STACKOVERFLOW,        "md6 stack overflow (message too long)" },
    { EXTRA_E_MD6_NULLDATA,             "null data pointer to md6" },
    { EXTRA_E_MD6_NULL_N,               "md6 compress: N is null" },
    { EXTRA_E_MD6_NULL_B,               "md6 standard compress: B is null" },
    { EXTRA_E_MD6_BAD_ELL,              "md6 standard compress: ell not in {0,255}" },
    { EXTRA_E_MD6_BAD_p,                "md6 standard compress: p<0 or p>b*w" },
    { EXTRA_E_MD6_NULL_K,               "md6 standard compress: K is null" },
    { EXTRA_E_MD6_NULL_Q,               "md6 standard compress: Q is null" },
    { EXTRA_E_MD6_NULL_C,               "md6 standard compress: C is null" },
    { EXTRA_E_MD6_BAD_L,                "md6 standard compress or init: L<0 or L>255" },
    { EXTRA_E_MD6_BAD_r,                "md6 compress or init: r<0 or r>255" },
    { EXTRA_E_MD6_OUT_OF_MEMORY,        "md6 compress: storage allocation failed" },
    { 0, NULL }
};

/*********************************************************************
 *
 *  Provider context
 *
 *****/

static void provider_ctx_free(struct provider_ctx_st *ctx)
{
    if (ctx != NULL)
        proverr_free_handle(ctx->proverr_handle);
    free(ctx);
}

static struct provider_ctx_st *provider_ctx_new(const OSSL_CORE_HANDLE *core,
                                                const OSSL_DISPATCH *in)
{
    struct provider_ctx_st *ctx;

    if ((ctx = malloc(sizeof(*ctx))) != NULL
        && (ctx->proverr_handle = proverr_new_handle(core, in)) != NULL) {
        ctx->core_handle = core;
    } else {
        provider_ctx_free(ctx);
        ctx = NULL;
    }
    return ctx;
}

/*********************************************************************
 *
 *  Setup
 *
 *****/

/* The table of digests this provider offers */
static const OSSL_ALGORITHM digests[] = {
    { "md6", "x.author='" AUTHOR "'", o_md6_functions },
    { "md6-224", "x.author='" AUTHOR "'", o_md6_224_functions },
    { "md6-256", "x.author='" AUTHOR "'", o_md6_256_functions },
    { "md6-384", "x.author='" AUTHOR "'", o_md6_384_functions },
    { "md6-512", "x.author='" AUTHOR "'", o_md6_512_functions },
    { NULL , NULL, NULL }
};

/* The table of kdfs this provider offers */
static const OSSL_ALGORITHM kdfs[] = {
    { "crypt", "x.author='" AUTHOR "'", crypt_functions },
    { NULL , NULL, NULL }
};

/*
 * Forward declarations to ensure we get signatures right.  All the
 * OSSL_FUNC_* types come from <openssl/core_dispatch.h>
 */
static OSSL_FUNC_provider_query_operation_fn extra_prov_operation;
static OSSL_FUNC_provider_get_params_fn extra_prov_get_params;
static OSSL_FUNC_provider_get_reason_strings_fn extra_prov_get_reason_strings;

/* The function that returns the appropriate algorithm table per operation */
static const OSSL_ALGORITHM *extra_prov_operation(void *vprovctx,
                                                     int operation_id,
                                                     int *no_cache)
{
    *no_cache = 0;
    switch (operation_id) {
    case OSSL_OP_KDF:
        return kdfs;
    case OSSL_OP_DIGEST:
        return digests;
    }
    return NULL;
}

static const OSSL_ITEM *extra_prov_get_reason_strings(void *provctx)
{
    return reason_strings;
}

static int extra_prov_get_params(void *provctx, OSSL_PARAM *params)
{
    OSSL_PARAM *p;
    int ok = 1;

    for(p = params; p->key != NULL; p++)
        if (strcasecmp(p->key, "version") == 0) {
            *(const void **)p->data = VERSION;
            p->return_size = strlen(VERSION);
        } else if (strcasecmp(p->key, "buildinfo") == 0
                   && BUILDTYPE[0] != '\0') {
            *(const void **)p->data = BUILDTYPE;
            p->return_size = strlen(BUILDTYPE);
        } else if (strcasecmp(p->key, "author") == 0
                   && AUTHOR[0] != '\0') {
            *(const void **)p->data = AUTHOR;
            p->return_size = strlen(AUTHOR);
        }
    return ok;
}

/* The function that tears down this provider */
static void extra_prov_teardown(void *vprovctx)
{
    provider_ctx_free(vprovctx);
}

/* The base dispatch table */
static const OSSL_DISPATCH provider_functions[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (funcptr_t)extra_prov_teardown },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (funcptr_t)extra_prov_operation },
    { OSSL_FUNC_PROVIDER_GET_REASON_STRINGS,
      (funcptr_t)extra_prov_get_reason_strings },
    { OSSL_FUNC_PROVIDER_GET_PARAMS,
      (funcptr_t)extra_prov_get_params },
    { 0, NULL }
};

int OSSL_provider_init(const OSSL_CORE_HANDLE *core,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **vprovctx)
{
    if ((*vprovctx = provider_ctx_new(core, in)) == NULL)
        return 0;
    *out = provider_functions;
    return 1;
}
