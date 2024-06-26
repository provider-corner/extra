// SPDX-FileCopyrightText: 2022-2024 "extra" provider collective
//
// SPDX-License-Identifier: LGPL-3.0-or-later

/* CC-BY license applied, see LICENCE.md */

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <openssl/core.h>
#include <openssl/core_dispatch.h>

#include "prov/err.h"
#include "prov/num.h"

#include "export.h"
#include "e_params.h"
#include "local.h"
#include "crypt_data.h"
#include "md6_data.h"

/*********************************************************************
 *
 *  Errors
 *
 *****/

static const OSSL_ITEM reason_strings[] = {
    GLOBAL_EXTRA_REASONS,
    CRYPT_REASONS,
    MD6_REASONS,
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
    MD6_ALGORITHMS("provider=extra"),
    { NULL , NULL, NULL }
};

/* The table of kdfs this provider offers */
static const OSSL_ALGORITHM kdfs[] = {
    CRYPT_ALGORITHMS("provider=extra"),
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
        switch (extra_params_parse(p->key)) {
        case V_PARAM_version:
            *(const void **)p->data = VERSION;
            p->return_size = strlen(VERSION);
            break;
        case V_PARAM_buildinfo:
            if (BUILDTYPE[0] != '\0') {
                *(const void **)p->data = BUILDTYPE;
                p->return_size = strlen(BUILDTYPE);
            }
            break;
        case V_PARAM_author:
            if (AUTHOR[0] != '\0') {
                *(const void **)p->data = AUTHOR;
                p->return_size = strlen(AUTHOR);
            }
            break;
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

EXTRA_EXPORT int
OSSL_provider_init(const OSSL_CORE_HANDLE *core,
                   const OSSL_DISPATCH *in,
                   const OSSL_DISPATCH **out,
                   void **vprovctx)
{
    if ((*vprovctx = provider_ctx_new(core, in)) == NULL)
        return 0;
    *out = provider_functions;
    return 1;
}
