// SPDX-FileCopyrightText: 2022-2024 "extra" provider collective
//
// SPDX-License-Identifier: LGPL-3.0-or-later

/* CC-BY license applied, see LICENCE.md */

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/err.h>

#include "external/md6/md6.h"

#include "prov/err.h"
#include "prov/num.h"

#include "e_params.h"
#include "local.h"
#include "md6_data.h"

#if 0
/* Compression hook copied from md6sum.c */
int  print_input_output = 1;
int  print_intermediate = 1;

void compression_hook_1(md6_word *C,
			const md6_word *Q,
			md6_word *K,
			int ell,
			int ii,
			int r,
			int L,
			int z,
			int p,
			int keylen,
			int d,
			md6_word *B
)
{ int i;
  md6_word A[5000];

  md6_pack(A,Q,K,ell,ii,r,L,z,p,keylen,d,B);

  md6_main_compression_loop( A, r);

  if (ell==1 && ii==0)
    { 
      fprintf(stderr,"-- d = %6d (digest length in bits)\n",d);
      fprintf(stderr,"-- L = %6d (number of parallel passes)\n",L);
      fprintf(stderr,"-- r = %6d (number of rounds)\n",r);
      /* print key out as chars, since for md6sum it is essentially
      ** impossible to enter non-char keys...
      */
      fprintf(stderr,"-- K = '");
      for (i=0;i<keylen;i++) 
	fprintf(stderr,"%c",(int)(K[i/(md6_w/8)]>>8*(7-(i%(md6_w/8))))&0xff);
      fprintf(stderr,"' (key)\n");
      fprintf(stderr,"-- k = %6d (key length in bytes)\n",keylen);
      fprintf(stderr,"\n");
    }

  fprintf(stderr,"MD6 compression function computation ");
  fprintf(stderr,"(level %d, index %d):\n",ell,ii);
  fprintf(stderr,"Input (%d words):\n",md6_n);

  for (i=0;i<r*md6_c+md6_n;i++)
    {
      if ((i<md6_q))
	{ fprintf(stderr,"A[%4d] = " PR_MD6_WORD,i,A[i]);
	  fprintf(stderr," Q[%d]\n",i);
	}
      else if ((i>=md6_q)&&(i<md6_q+md6_k))
	{ fprintf(stderr,"A[%4d] = " PR_MD6_WORD,i,A[i]);
	  fprintf(stderr," key K[%d]\n",i-md6_q);
	}
      else if ((md6_u>0)&&(i==md6_q+md6_k+md6_u-1))
	{ fprintf(stderr,"A[%4d] = " PR_MD6_WORD,i,A[i]);
	  fprintf(stderr," nodeID U = (ell,i) = (%d,%d)\n",ell,ii);
	}
      else if ((md6_v>0)&&(i==md6_q+md6_k+md6_u+md6_v-1))
	{ fprintf(stderr,"A[%4d] = " PR_MD6_WORD,i,A[i]);
	  fprintf(stderr," control word V = "
		          "(r,L,z,p,keylen,d) = "
		  "(%d,%d,%d,%d,%d,%d)\n",r,L,z,p,keylen,d);
	}
      else if ((i>=md6_q+md6_k+md6_u+md6_v)&&(i<md6_n))
	{ fprintf(stderr,"A[%4d] = " PR_MD6_WORD,i,A[i]);
	  fprintf(stderr," data B[%2d] ",i-md6_q-md6_k-md6_u-md6_v);
	  if (ell < L+1) /* PAR node */
	    { if (ell == 1)
		{ if ( (i+(p/md6_w))<md6_n )
		    fprintf(stderr,"input message word %4d",
			    ii*md6_b+(i-(md6_q+md6_k+md6_u+md6_v)));
		  else
		    fprintf(stderr,"padding");
		}
	      else
		if ( (i+(p/md6_w))< md6_n )
		  fprintf(stderr,
			  "chaining from (%d,%d)",
			  ell-1,
			  4*ii+(i-(md6_q+md6_k+md6_u+md6_v))/md6_c);
		else 
		  fprintf(stderr,"padding");
	    }
	  else /* SEQ node: ell == L+1 */
	    { if (i-(md6_q+md6_k+md6_u+md6_v)<md6_c) /* initial portion: IV or chaining */
		{ if (ii == 0)
		    fprintf(stderr,"IV");
		  else
		    fprintf(stderr,"chaining from (%d,%d)",ell,ii-1);
		}
	      else /* data, chaining from below, or padding */
		{ if (i+(p/md6_w)>=md6_n)
		    fprintf(stderr,"padding");
		  else if (ell == 1)
		    fprintf(stderr,"input message word %4d",
			    ii*(md6_b-md6_c)+(i-(md6_q+md6_k+md6_u+md6_v+md6_c)));
		  else 
		    fprintf(stderr,
			    "chaining from (%d,%d)",
			    ell-1,
			    3*ii+(i-(md6_q+md6_k+md6_u+md6_v+md6_c))/md6_c);
		}
	    }
	  fprintf(stderr,"\n");
	}
      else if ((i>=r*md6_c+md6_n-md6_c))
	{ if ((i==r*md6_c+md6_n-md6_c))
	    fprintf(stderr,"Output (%d words of chaining values):\n",md6_c);
	  fprintf(stderr,"A[%4d] = " PR_MD6_WORD,i,A[i]);
	  fprintf(stderr," output chaining value C[%d]\n",i-(r*md6_c+md6_n-md6_c));
	}
      else 
	{ if (i==md6_n)
	    { if (print_intermediate)
		fprintf(stderr,"Intermediate values:\n");
	      else
		fprintf(stderr,
			"Intermediate values A[%d..%d] omitted... "
			"\n",md6_n,r*md6_c+md6_n-md6_c-1);
	    }
	  if (print_intermediate)
	    fprintf(stderr,"A[%4d] = " PR_MD6_WORD "\n",i,A[i]);
	}
    }
  fprintf(stderr,"\n");
}
#endif

/*
 * Forward declarations to ensure we get signatures right.  All the
 * OSSL_FUNC_* types come from <openssl/core_dispatch.h>
 *
 * All symbols in here start with 'o_md6_' to avoid clashes with symbols
 * defined in external/md6/,ḿd6.h
 */
static OSSL_FUNC_digest_newctx_fn o_md6_newctx;
static OSSL_FUNC_digest_newctx_fn o_md6_256_newctx;
static OSSL_FUNC_digest_newctx_fn o_md6_512_newctx;
static OSSL_FUNC_digest_freectx_fn o_md6_freectx;
static OSSL_FUNC_digest_dupctx_fn o_md6_dupctx;

static OSSL_FUNC_digest_init_fn o_md6_init;
static OSSL_FUNC_digest_update_fn o_md6_update;
static OSSL_FUNC_digest_final_fn o_md6_final;

static OSSL_FUNC_digest_get_params_fn o_md6_get_params;
static OSSL_FUNC_digest_get_params_fn o_md6_224_get_params;
static OSSL_FUNC_digest_get_params_fn o_md6_256_get_params;
static OSSL_FUNC_digest_get_params_fn o_md6_384_get_params;
static OSSL_FUNC_digest_get_params_fn o_md6_512_get_params;
static OSSL_FUNC_digest_gettable_params_fn o_md6_gettable_params;
static OSSL_FUNC_digest_set_ctx_params_fn o_md6_set_ctx_params;
static OSSL_FUNC_digest_get_ctx_params_fn o_md6_get_ctx_params;
static OSSL_FUNC_digest_settable_ctx_params_fn o_md6_settable_ctx_params;
static OSSL_FUNC_digest_gettable_ctx_params_fn o_md6_gettable_ctx_params;

/*
 * The context used throughout all these functions.
 */
struct o_md6_ctx_st {
    struct provider_ctx_st *provctx;

    /* Hash bit length */
    size_t hash_bits;
    size_t hash_size;
    int hash_bits_hard_coded;

    /* rounds (r) */
    int rounds;

    /* mode (L) */
    int mode;

    /* State */
    md6_state st;
};
#define ERR_HANDLE(ctx) ((ctx)->provctx->proverr_handle)

static void set_defaults(struct o_md6_ctx_st *ctx)
{
    const char *env_val;

    if (!ctx->hash_bits_hard_coded) {
        if ((env_val = getenv("MD6_BITS")) != NULL) {
            size_t bits = strtoul(env_val, NULL, 0);

            /* ctx_init detects if the number of bits is wrong */
            ctx->hash_bits = bits;
        }
    }
    ctx->hash_size = ctx->hash_bits / 8;

    ctx->mode = md6_default_L;
    if ((env_val = getenv("MD6_MODE")) != NULL)
        ctx->mode = atoi(env_val);

    /* Stolen from md6_default_r in external/md6/md6_mode.c */
    ctx->rounds = 40 + ctx->hash_size * 8 / 4;
    if ((env_val = getenv("MD6_ROUNDS")) != NULL)
        ctx->rounds = atoi(env_val);
}

static void ctx_init_0(struct o_md6_ctx_st *ctx)
{
    ctx->hash_bits = 0;
}

static struct o_md6_ctx_st *newctx_init(void *vprovctx,
                                        void (*init)(struct o_md6_ctx_st *ctx))
{
    struct o_md6_ctx_st *ctx;

    if ((ctx = malloc(sizeof(*ctx))) != NULL) {
        memset(ctx, 0, sizeof(*ctx));
        ctx->provctx = vprovctx;

        /* variant specific init */
        init(ctx);

        /* defaults */
        set_defaults(ctx);

        /* Check that everything seems correct */
        if (ctx->hash_bits == 0 || ctx->hash_bits % 8 != 0) {
            ERR_raise_data(ERR_HANDLE(ctx), EXTRA_E_INVALID_OUTPUT_SIZE,
                           "hash output size in bits must be multiple of 8, "
                           "but is set to %zu", ctx->hash_bits);
            free(ctx);
            ctx = NULL;
        }
    }
    return ctx;
}

static void *o_md6_newctx(void *vprovctx)
{
    return newctx_init(vprovctx, ctx_init_0);
}

static void o_md6_freectx(void *vctx)
{
    struct o_md6_ctx_st *ctx = vctx;

    ctx->provctx = NULL;
    free(ctx);
}

static void *o_md6_dupctx(void *vctx)
{
    struct o_md6_ctx_st *src = vctx;
    struct o_md6_ctx_st *dst = NULL;

    if (src == NULL
        || (dst = o_md6_newctx(NULL)) == NULL)

    dst->provctx = src->provctx;
    dst->provctx->proverr_handle =
        proverr_dup_handle(src->provctx->proverr_handle);

    return dst;
}

static int o_md6_init(void *vctx, const OSSL_PARAM params[])
{
    struct o_md6_ctx_st *ctx = vctx;
    int rc;

    if (!o_md6_set_ctx_params(ctx, params))
        return 0;

    rc = md6_full_init(&ctx->st, ctx->hash_size * 8, NULL, 0,
                       ctx->mode, ctx->rounds);
    if (rc != MD6_SUCCESS) {
        ERR_raise(ERR_HANDLE(ctx), EXTRA_E_MD6__BASE + rc);
        return 0;
    }
#if 0
    compression_hook = compression_hook_1;
#endif
    return 1;
}

static int o_md6_update(void *vctx, const unsigned char *in, size_t inl)
{
    struct o_md6_ctx_st *ctx = vctx;
    int rc;

    /*
     * md6_update() takes the number of bits as a uint64_t, so we
     * must ensure that |inl| isn't larger than that in bits.
     * If sizeof(inl) is less than sizeof(uint64_t), there's no point checking.
     */
    if (sizeof(inl) >= sizeof(uint64_t) - 1
        && inl > ((((uint64_t)1)<<56) - 1)) {
        ERR_raise(ERR_HANDLE(ctx), EXTRA_E_INVALID_INPUT_LENGTH);
        return 0;
    }
    rc = md6_update(&ctx->st, (unsigned char *)in, (uint64_t)inl << 3);
    if (rc != MD6_SUCCESS) {
        ERR_raise(ERR_HANDLE(ctx), EXTRA_E_MD6__BASE + rc);
        return 0;
    }
    return 1;
}

static int o_md6_final(void *vctx, unsigned char *out, size_t *outl,
                                   size_t outsz)
{
    struct o_md6_ctx_st *ctx = vctx;
    int rc;

    /*
     * md6_final() produces a hash value that's ctx->hash_size
     * bytes long, so we must ensure that the output size is at least
     * that size.
     * md6_update() takes the number of bits as a uint64_t, so we
     * must ensure that |inl| isn't larger than that in bits.
     */
    if (outsz < ctx->hash_size) {
        ERR_raise(ERR_HANDLE(ctx), EXTRA_E_OUTPUT_SIZE_TOO_SMALL);
        return 0;
    }
    rc = md6_final(&ctx->st, out);
    if (rc != MD6_SUCCESS) {
        ERR_raise(ERR_HANDLE(ctx), EXTRA_E_MD6__BASE + rc);
        return 0;
    }
    *outl = ctx->hash_size;
    return 1;
}

/* Parameter handling */
# define common_table                                                   \
    { S_PARAM_rounds, OSSL_PARAM_INTEGER, NULL, sizeof(int), 0 },       \
    { S_PARAM_mode, OSSL_PARAM_INTEGER, NULL, sizeof(int), 0 }

/* Parameters that libcrypto can get from this implementation */
static const OSSL_PARAM *o_md6_gettable_params(void *provctx)
{
    static const OSSL_PARAM table[] = {
        { S_PARAM_size, OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0 },
        common_table,
        { NULL, 0, NULL, 0, 0 },
    };

    return table;
}

static int o_md6_get_params(OSSL_PARAM params[])
{
    struct o_md6_ctx_st fake_ctx = { 0, };

    set_defaults(&fake_ctx);
    return o_md6_get_ctx_params(&fake_ctx, params);
}

/* Parameters that libcrypto can get from the context */
static const OSSL_PARAM *o_md6_gettable_ctx_params(void *vctx, void *provctx)
{
    static const OSSL_PARAM table[] = {
        { S_PARAM_size, OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0 },
        common_table,
        { NULL, 0, NULL, 0, 0 },
    };

    return table;
}

static int o_md6_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    struct o_md6_ctx_st *ctx = vctx;
    int ok = 1;

    for (p = params; p->key != NULL; p++)
        switch (extra_params_parse(p->key)) {
        case V_PARAM_size:
            ok &= (provnum_set_size_t(p, ctx->hash_size) >= 0);
            break;
        case V_PARAM_rounds:
            ok &= (provnum_set_int(p, ctx->rounds) >= 0);
            break;
        case V_PARAM_mode:
            ok &= (provnum_set_int(p, ctx->mode) >= 0);
            break;
        }
    return ok;
}

/* Parameters that libcrypto can send to the context */
static const OSSL_PARAM *o_md6_settable_ctx_params(void *vctx, void *provctx)
{
    static const OSSL_PARAM table[] = {
        { S_PARAM_size, OSSL_PARAM_INTEGER, NULL, sizeof(size_t), 0 },
        common_table,
        { NULL, 0, NULL, 0, 0 },
    };
    static const OSSL_PARAM table_hard_coded[] = {
        common_table,
        { NULL, 0, NULL, 0, 0 },
    };
    struct o_md6_ctx_st *ctx = vctx;

    if (ctx->hash_bits_hard_coded)
        return table_hard_coded;
    return table;
}

static int o_md6_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    struct o_md6_ctx_st *ctx = vctx;
    const OSSL_PARAM *p;
    int ok = 1;
    char *env_val;

    if (params != NULL)
        for (p = params; p->key != NULL; p++)
            switch (extra_params_parse(p->key)) {
            case V_PARAM_size:
                if (ctx->hash_bits_hard_coded) {
                    ERR_raise_data(ERR_HANDLE(ctx), EXTRA_E_HARD_CODED_VALUE,
                                   "size");
                    ok = 0;
                } else if (provnum_get_size_t(&ctx->hash_size, p) < 0) {
                    ok = 0;
                } else {
                    ctx->hash_bits = ctx->hash_size * 8;
                }
                break;
            case V_PARAM_rounds:
                ok &= (provnum_get_int(&ctx->rounds, p) >= 0);
                break;
            case V_PARAM_mode:
                ok &= (provnum_get_int(&ctx->mode, p) >= 0);
                break;
            }
    return ok;
}

/* The generic md6 dispatch tables */
const OSSL_DISPATCH o_md6_functions[] = {
    { OSSL_FUNC_DIGEST_NEWCTX, (funcptr_t)o_md6_newctx },
    { OSSL_FUNC_DIGEST_FREECTX, (funcptr_t)o_md6_freectx },
    { OSSL_FUNC_DIGEST_DUPCTX, (funcptr_t)o_md6_dupctx },
    { OSSL_FUNC_DIGEST_INIT, (funcptr_t)o_md6_init },
    { OSSL_FUNC_DIGEST_UPDATE, (funcptr_t)o_md6_update },
    { OSSL_FUNC_DIGEST_FINAL, (funcptr_t)o_md6_final },
    { OSSL_FUNC_DIGEST_GET_PARAMS, (funcptr_t)o_md6_get_params },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS, (funcptr_t)o_md6_gettable_params },
    { OSSL_FUNC_DIGEST_GET_CTX_PARAMS, (funcptr_t)o_md6_get_ctx_params },
    { OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS, (funcptr_t)o_md6_gettable_ctx_params },
    { OSSL_FUNC_DIGEST_SET_CTX_PARAMS, (funcptr_t)o_md6_set_ctx_params },
    { OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS,
      (funcptr_t)o_md6_settable_ctx_params },
    { 0, NULL }
};

static void ctx_init_128(struct o_md6_ctx_st *ctx)
{
    ctx->hash_bits_hard_coded = 1;
    ctx->hash_bits = 128;
}

static void *o_md6_128_newctx(void *vprovctx)
{
    return newctx_init(vprovctx, ctx_init_128);
}

static int o_md6_128_get_params(OSSL_PARAM params[])
{
    struct o_md6_ctx_st fake_ctx = { 0, };

    ctx_init_128(&fake_ctx);
    set_defaults(&fake_ctx);
    return o_md6_get_ctx_params(&fake_ctx, params);
}

/* The md6-128 dispatch tables */
const OSSL_DISPATCH o_md6_128_functions[] = {
    { OSSL_FUNC_DIGEST_NEWCTX, (funcptr_t)o_md6_128_newctx },
    { OSSL_FUNC_DIGEST_FREECTX, (funcptr_t)o_md6_freectx },
    { OSSL_FUNC_DIGEST_DUPCTX, (funcptr_t)o_md6_dupctx },
    { OSSL_FUNC_DIGEST_INIT, (funcptr_t)o_md6_init },
    { OSSL_FUNC_DIGEST_UPDATE, (funcptr_t)o_md6_update },
    { OSSL_FUNC_DIGEST_FINAL, (funcptr_t)o_md6_final },
    { OSSL_FUNC_DIGEST_GET_PARAMS, (funcptr_t)o_md6_128_get_params },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS, (funcptr_t)o_md6_gettable_params },
    { OSSL_FUNC_DIGEST_GET_CTX_PARAMS, (funcptr_t)o_md6_get_ctx_params },
    { OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS, (funcptr_t)o_md6_gettable_ctx_params },
    { OSSL_FUNC_DIGEST_SET_CTX_PARAMS, (funcptr_t)o_md6_set_ctx_params },
    { OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS, (funcptr_t)o_md6_settable_ctx_params },
    { 0, NULL }
};

static void ctx_init_224(struct o_md6_ctx_st *ctx)
{
    ctx->hash_bits_hard_coded = 1;
    ctx->hash_bits = 224;
}

static void *o_md6_224_newctx(void *vprovctx)
{
    return newctx_init(vprovctx, ctx_init_224);
}

static int o_md6_224_get_params(OSSL_PARAM params[])
{
    struct o_md6_ctx_st fake_ctx = { 0, };

    ctx_init_224(&fake_ctx);
    set_defaults(&fake_ctx);
    return o_md6_get_ctx_params(&fake_ctx, params);
}

/* The md6-224 dispatch tables */
const OSSL_DISPATCH o_md6_224_functions[] = {
    { OSSL_FUNC_DIGEST_NEWCTX, (funcptr_t)o_md6_224_newctx },
    { OSSL_FUNC_DIGEST_FREECTX, (funcptr_t)o_md6_freectx },
    { OSSL_FUNC_DIGEST_DUPCTX, (funcptr_t)o_md6_dupctx },
    { OSSL_FUNC_DIGEST_INIT, (funcptr_t)o_md6_init },
    { OSSL_FUNC_DIGEST_UPDATE, (funcptr_t)o_md6_update },
    { OSSL_FUNC_DIGEST_FINAL, (funcptr_t)o_md6_final },
    { OSSL_FUNC_DIGEST_GET_PARAMS, (funcptr_t)o_md6_224_get_params },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS, (funcptr_t)o_md6_gettable_params },
    { OSSL_FUNC_DIGEST_GET_CTX_PARAMS, (funcptr_t)o_md6_get_ctx_params },
    { OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS, (funcptr_t)o_md6_gettable_ctx_params },
    { OSSL_FUNC_DIGEST_SET_CTX_PARAMS, (funcptr_t)o_md6_set_ctx_params },
    { OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS, (funcptr_t)o_md6_settable_ctx_params },
    { 0, NULL }
};

static void ctx_init_256(struct o_md6_ctx_st *ctx)
{
    ctx->hash_bits_hard_coded = 1;
    ctx->hash_bits = 256;
}

static void *o_md6_256_newctx(void *vprovctx)
{
    return newctx_init(vprovctx, ctx_init_256);
}

static int o_md6_256_get_params(OSSL_PARAM params[])
{
    struct o_md6_ctx_st fake_ctx = { 0, };

    ctx_init_256(&fake_ctx);
    set_defaults(&fake_ctx);
    return o_md6_get_ctx_params(&fake_ctx, params);
}

/* The md6-256 dispatch tables */
const OSSL_DISPATCH o_md6_256_functions[] = {
    { OSSL_FUNC_DIGEST_NEWCTX, (funcptr_t)o_md6_256_newctx },
    { OSSL_FUNC_DIGEST_FREECTX, (funcptr_t)o_md6_freectx },
    { OSSL_FUNC_DIGEST_DUPCTX, (funcptr_t)o_md6_dupctx },
    { OSSL_FUNC_DIGEST_INIT, (funcptr_t)o_md6_init },
    { OSSL_FUNC_DIGEST_UPDATE, (funcptr_t)o_md6_update },
    { OSSL_FUNC_DIGEST_FINAL, (funcptr_t)o_md6_final },
    { OSSL_FUNC_DIGEST_GET_PARAMS, (funcptr_t)o_md6_256_get_params },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS, (funcptr_t)o_md6_gettable_params },
    { OSSL_FUNC_DIGEST_GET_CTX_PARAMS, (funcptr_t)o_md6_get_ctx_params },
    { OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS, (funcptr_t)o_md6_gettable_ctx_params },
    { OSSL_FUNC_DIGEST_SET_CTX_PARAMS, (funcptr_t)o_md6_set_ctx_params },
    { OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS, (funcptr_t)o_md6_settable_ctx_params },
    { 0, NULL }
};

static void ctx_init_384(struct o_md6_ctx_st *ctx)
{
    ctx->hash_bits_hard_coded = 1;
    ctx->hash_bits = 384;
}

static void *o_md6_384_newctx(void *vprovctx)
{
    return newctx_init(vprovctx, ctx_init_384);
}

static int o_md6_384_get_params(OSSL_PARAM params[])
{
    struct o_md6_ctx_st fake_ctx = { 0, };

    ctx_init_384(&fake_ctx);
    set_defaults(&fake_ctx);
    return o_md6_get_ctx_params(&fake_ctx, params);
}

/* The md6-384 dispatch tables */
const OSSL_DISPATCH o_md6_384_functions[] = {
    { OSSL_FUNC_DIGEST_NEWCTX, (funcptr_t)o_md6_384_newctx },
    { OSSL_FUNC_DIGEST_FREECTX, (funcptr_t)o_md6_freectx },
    { OSSL_FUNC_DIGEST_DUPCTX, (funcptr_t)o_md6_dupctx },
    { OSSL_FUNC_DIGEST_INIT, (funcptr_t)o_md6_init },
    { OSSL_FUNC_DIGEST_UPDATE, (funcptr_t)o_md6_update },
    { OSSL_FUNC_DIGEST_FINAL, (funcptr_t)o_md6_final },
    { OSSL_FUNC_DIGEST_GET_PARAMS, (funcptr_t)o_md6_384_get_params },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS, (funcptr_t)o_md6_gettable_params },
    { OSSL_FUNC_DIGEST_GET_CTX_PARAMS, (funcptr_t)o_md6_get_ctx_params },
    { OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS, (funcptr_t)o_md6_gettable_ctx_params },
    { OSSL_FUNC_DIGEST_SET_CTX_PARAMS, (funcptr_t)o_md6_set_ctx_params },
    { OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS, (funcptr_t)o_md6_settable_ctx_params },
    { 0, NULL }
};

static void ctx_init_512(struct o_md6_ctx_st *ctx)
{
    ctx->hash_bits_hard_coded = 1;
    ctx->hash_bits = 512;
}

static void *o_md6_512_newctx(void *vprovctx)
{
    return newctx_init(vprovctx, ctx_init_512);
}

static int o_md6_512_get_params(OSSL_PARAM params[])
{
    struct o_md6_ctx_st fake_ctx = { 0, };

    ctx_init_512(&fake_ctx);
    set_defaults(&fake_ctx);
    return o_md6_get_ctx_params(&fake_ctx, params);
}

/* The md6-512 dispatch tables */
const OSSL_DISPATCH o_md6_512_functions[] = {
    { OSSL_FUNC_DIGEST_NEWCTX, (funcptr_t)o_md6_512_newctx },
    { OSSL_FUNC_DIGEST_FREECTX, (funcptr_t)o_md6_freectx },
    { OSSL_FUNC_DIGEST_DUPCTX, (funcptr_t)o_md6_dupctx },
    { OSSL_FUNC_DIGEST_INIT, (funcptr_t)o_md6_init },
    { OSSL_FUNC_DIGEST_UPDATE, (funcptr_t)o_md6_update },
    { OSSL_FUNC_DIGEST_FINAL, (funcptr_t)o_md6_final },
    { OSSL_FUNC_DIGEST_GET_PARAMS, (funcptr_t)o_md6_512_get_params },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS, (funcptr_t)o_md6_gettable_params },
    { OSSL_FUNC_DIGEST_GET_CTX_PARAMS, (funcptr_t)o_md6_get_ctx_params },
    { OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS, (funcptr_t)o_md6_gettable_ctx_params },
    { OSSL_FUNC_DIGEST_SET_CTX_PARAMS, (funcptr_t)o_md6_set_ctx_params },
    { OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS, (funcptr_t)o_md6_settable_ctx_params },
    { 0, NULL }
};
