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

#include "local.h"

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
static OSSL_FUNC_digest_gettable_params_fn o_md6_gettable_params;
static OSSL_FUNC_digest_get_params_fn o_md6_256_get_params;
static OSSL_FUNC_digest_gettable_params_fn o_md6_256_gettable_params;
static OSSL_FUNC_digest_get_params_fn o_md6_512_get_params;
static OSSL_FUNC_digest_gettable_params_fn o_md6_512_gettable_params;
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
    size_t hash_size;
    int hash_size_hard_coded;
    int hash_size_set;

    /* rounds (r) */
    int rounds;
    int rounds_set;

    /* mode (L) */
    int mode;
    int mode_set;

    /* State */
    md6_state st;
};
#define ERR_HANDLE(ctx) ((ctx)->provctx->proverr_handle)

static void *o_md6_newctx(void *vprovctx)
{
    struct o_md6_ctx_st *ctx = malloc(sizeof(*ctx));

    if (ctx != NULL) {
        memset(ctx, 0, sizeof(*ctx));
        ctx->provctx = vprovctx;
    }
    return ctx;
}

static int o_md6_set_defaults(struct o_md6_ctx_st *ctx)
{
    if (!ctx->mode_set)
        ctx->mode = md6_default_L;
    if (!ctx->rounds_set)
        /* Stolen from md6_default_r in external/md6/md6_mode.c */
        ctx->rounds = 40 + ctx->hash_size * 8 / 4;
    return 1;
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

    o_md6_set_defaults(ctx);
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
     */
    if (inl > (((size_t)1)<<56 - 1)) {
        ERR_raise(ERR_HANDLE(ctx), EXTRA_E_INVALID_INPUT_LENGTH);
        return 0;
    }
    rc = md6_update(&ctx->st, (unsigned char *)in, inl << 3);
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

/* Parameters that libcrypto can get from the context */
static const OSSL_PARAM *o_md6_gettable_ctx_params(void *vctx, void *provctx)
{
    static const OSSL_PARAM table[] = {
        { "size", OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0 },
        { NULL, 0, NULL, 0, 0 },
    };

    return table;
}

static int o_md6_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    struct o_md6_ctx_st *ctx = vctx;
    int ok = 1;

    for (p = params; p->key != NULL; p++) {
        if (strcasecmp(p->key, "size") == 0)
            if (provnum_set_int(p, ctx->hash_size) < 0) {
                ok = 0;
                continue;
            }
    }
    return ok;
}

/* Parameters that libcrypto can send to the context */
static const OSSL_PARAM *o_md6_settable_ctx_params(void *vctx, void *provctx)
{
# define common_table                                           \
    { "rounds", OSSL_PARAM_INTEGER, NULL, sizeof(int), 0 },     \
    { "mode", OSSL_PARAM_INTEGER, NULL, sizeof(int), 0 }

    static const OSSL_PARAM table[] = {
        common_table,
        { "size", OSSL_PARAM_INTEGER, NULL, sizeof(size_t), 0 },
        { NULL, 0, NULL, 0, 0 },
    };
    static const OSSL_PARAM table_hard_coded[] = {
        common_table,
        { NULL, 0, NULL, 0, 0 },
    };
    struct o_md6_ctx_st *ctx = vctx;

    if (ctx->hash_size_hard_coded)
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
        for (p = params; p->key != NULL; p++) {
            if (strcasecmp(p->key, "size") == 0) {
                if (ctx->hash_size_hard_coded) {
                    ERR_raise_data(ERR_HANDLE(ctx), EXTRA_E_HARD_CODED_VALUE,
                                   "bits");
                    ok = 0;
                    continue;
                } else if (provnum_get_size_t(&ctx->hash_size, p) < 0) {
                    ok = 0;
                    continue;
                }
                ctx->hash_size_set = 1;
            } else if (strcasecmp(p->key, "rounds") == 0) {
                if (provnum_get_int(&ctx->rounds, p) < 0) {
                    ok = 0;
                    continue;
                }
                ctx->rounds_set = 1;
            } else if (strcasecmp(p->key, "mode") == 0) {
                if (provnum_get_int(&ctx->mode, p) < 0) {
                    ok = 0;
                    continue;
                }
                ctx->mode_set = 1;
            }
        }

    /*
     * Because 'openssl dgst' doesn't support digest params, we also
     * support environment variables as a fallback.
     */
    if (ok) {
        if (!ctx->hash_size_set && (env_val = getenv("MD6_SIZE")) != NULL) {
            ctx->hash_size = atoi(env_val);
            ctx->hash_size_set = 1;
        }
        if (!ctx->rounds_set && (env_val = getenv("MD6_ROUNDS")) != NULL) {
            ctx->rounds = atoi(env_val);
            ctx->rounds_set = 1;
        }
        if (!ctx->mode_set && (env_val = getenv("MD6_MODE")) != NULL) {
            ctx->mode = atoi(env_val);
            ctx->mode_set = 1;
        }
    }
    return ok;
}

/* Parameters that libcrypto can get from this implementation */
static const OSSL_PARAM *o_md6_gettable_params(void *provctx)
{
    static const OSSL_PARAM table[] = {
        { NULL, 0, NULL, 0, 0 },
    };

    return table;
}

static int o_md6_get_params(OSSL_PARAM params[])
{
    return 1;
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

static void *o_md6_224_newctx(void *vprovctx)
{
    struct o_md6_ctx_st *ctx = o_md6_newctx(vprovctx);

    if (ctx != NULL) {
        ctx->hash_size = 224 / 8;
        ctx->hash_size_hard_coded = 1;
        ctx->hash_size_set = 1;
    }
    return ctx;
}

/* Parameters that libcrypto can get from this implementation */
static const OSSL_PARAM *o_md6_224_gettable_params(void *provctx)
{
    static const OSSL_PARAM table[] = {
        { "size", OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0 },
        { NULL, 0, NULL, 0, 0 },
    };

    return table;
}

static int o_md6_224_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    int ok = 1;

    for (p = params; p->key != NULL; p++) {
        if (strcasecmp(p->key, "size") == 0)
            if (provnum_set_size_t(p, 224 / 8) < 0) {
                ok = 0;
                continue;
            }
    }
    return ok;
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
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS, (funcptr_t)o_md6_224_gettable_params },
    { OSSL_FUNC_DIGEST_GET_CTX_PARAMS, (funcptr_t)o_md6_get_ctx_params },
    { OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS, (funcptr_t)o_md6_gettable_ctx_params },
    { OSSL_FUNC_DIGEST_SET_CTX_PARAMS, (funcptr_t)o_md6_set_ctx_params },
    { OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS, (funcptr_t)o_md6_settable_ctx_params },
    { 0, NULL }
};

static void *o_md6_256_newctx(void *vprovctx)
{
    struct o_md6_ctx_st *ctx = o_md6_newctx(vprovctx);

    if (ctx != NULL) {
        ctx->hash_size = 256 / 8;
        ctx->hash_size_hard_coded = 1;
        ctx->hash_size_set = 1;
    }
    return ctx;
}

/* Parameters that libcrypto can get from this implementation */
static const OSSL_PARAM *o_md6_256_gettable_params(void *provctx)
{
    static const OSSL_PARAM table[] = {
        { "size", OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0 },
        { NULL, 0, NULL, 0, 0 },
    };

    return table;
}

static int o_md6_256_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    int ok = 1;

    for (p = params; p->key != NULL; p++) {
        if (strcasecmp(p->key, "size") == 0)
            if (provnum_set_size_t(p, 256 / 8) < 0) {
                ok = 0;
                continue;
            }
    }
    return ok;
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
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS, (funcptr_t)o_md6_256_gettable_params },
    { OSSL_FUNC_DIGEST_GET_CTX_PARAMS, (funcptr_t)o_md6_get_ctx_params },
    { OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS, (funcptr_t)o_md6_gettable_ctx_params },
    { OSSL_FUNC_DIGEST_SET_CTX_PARAMS, (funcptr_t)o_md6_set_ctx_params },
    { OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS, (funcptr_t)o_md6_settable_ctx_params },
    { 0, NULL }
};

static void *o_md6_384_newctx(void *vprovctx)
{
    struct o_md6_ctx_st *ctx = o_md6_newctx(vprovctx);

    if (ctx != NULL) {
        ctx->hash_size = 384 / 8;
        ctx->hash_size_hard_coded = 1;
        ctx->hash_size_set = 1;
    }
    return ctx;
}

/* Parameters that libcrypto can get from this implementation */
static const OSSL_PARAM *o_md6_384_gettable_params(void *provctx)
{
    static const OSSL_PARAM table[] = {
        { "size", OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0 },
        { NULL, 0, NULL, 0, 0 },
    };

    return table;
}

static int o_md6_384_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    int ok = 1;

    for (p = params; p->key != NULL; p++) {
        if (strcasecmp(p->key, "size") == 0)
            if (provnum_set_size_t(p, 384 / 8) < 0) {
                ok = 0;
                continue;
            }
    }
    return ok;
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
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS, (funcptr_t)o_md6_384_gettable_params },
    { OSSL_FUNC_DIGEST_GET_CTX_PARAMS, (funcptr_t)o_md6_get_ctx_params },
    { OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS, (funcptr_t)o_md6_gettable_ctx_params },
    { OSSL_FUNC_DIGEST_SET_CTX_PARAMS, (funcptr_t)o_md6_set_ctx_params },
    { OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS, (funcptr_t)o_md6_settable_ctx_params },
    { 0, NULL }
};

static void *o_md6_512_newctx(void *vprovctx)
{
    struct o_md6_ctx_st *ctx = o_md6_newctx(vprovctx);

    if (ctx != NULL) {
        ctx->hash_size = 512 / 8;
        ctx->hash_size_hard_coded = 1;
        ctx->hash_size_set = 1;
    }
    return ctx;
}

/* Parameters that libcrypto can get from this implementation */
static const OSSL_PARAM *o_md6_512_gettable_params(void *provctx)
{
    static const OSSL_PARAM table[] = {
        { "size", OSSL_PARAM_UNSIGNED_INTEGER, NULL, sizeof(size_t), 0 },
        { NULL, 0, NULL, 0, 0 },
    };

    return table;
}

static int o_md6_512_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    int ok = 1;

    for (p = params; p->key != NULL; p++) {
        if (strcasecmp(p->key, "size") == 0)
            if (provnum_set_size_t(p, 512 / 8) < 0) {
                ok = 0;
                continue;
            }
    }
    return ok;
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
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS, (funcptr_t)o_md6_512_gettable_params },
    { OSSL_FUNC_DIGEST_GET_CTX_PARAMS, (funcptr_t)o_md6_get_ctx_params },
    { OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS, (funcptr_t)o_md6_gettable_ctx_params },
    { OSSL_FUNC_DIGEST_SET_CTX_PARAMS, (funcptr_t)o_md6_set_ctx_params },
    { OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS, (funcptr_t)o_md6_settable_ctx_params },
    { 0, NULL }
};
