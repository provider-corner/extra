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
