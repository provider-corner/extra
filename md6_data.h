// SPDX-FileCopyrightText: 2023-2024 "extra" provider collective
//
// SPDX-License-Identifier: LGPL-3.0-or-later

/* CC-BY license applied, see LICENCE.md */

extern const OSSL_DISPATCH o_md6_functions[];
extern const OSSL_DISPATCH o_md6_128_functions[];
extern const OSSL_DISPATCH o_md6_224_functions[];
extern const OSSL_DISPATCH o_md6_256_functions[];
extern const OSSL_DISPATCH o_md6_384_functions[];
extern const OSSL_DISPATCH o_md6_512_functions[];

#define MD6_AUTHOR "@levitte"
#define MD6_ALGORITHMS(globalprops)                                     \
    { "md6", "provider=extra,x.author='" AUTHOR "'", o_md6_functions }, \
    { "md6-128", "provider=extra,x.author='" AUTHOR "'", o_md6_128_functions }, \
    { "md6-224", "provider=extra,x.author='" AUTHOR "'", o_md6_224_functions }, \
    { "md6-256", "provider=extra,x.author='" AUTHOR "'", o_md6_256_functions }, \
    { "md6-384", "provider=extra,x.author='" AUTHOR "'", o_md6_384_functions }, \
    { "md6-512", "provider=extra,x.author='" AUTHOR "'", o_md6_512_functions }

/* The following errors mimic the ones in external/md6/md6.h */
# define EXTRA_E_MD6__BASE                   200
# define EXTRA_E_MD6_FAIL                    201
# define EXTRA_E_MD6_BADHASHLEN              202
# define EXTRA_E_MD6_NULLSTATE               203
# define EXTRA_E_MD6_BADKEYLEN               204
# define EXTRA_E_MD6_STATENOTINIT            205
# define EXTRA_E_MD6_STACKUNDERFLOW          206
# define EXTRA_E_MD6_STACKOVERFLOW           207
# define EXTRA_E_MD6_NULLDATA                208
# define EXTRA_E_MD6_NULL_N                  209
# define EXTRA_E_MD6_NULL_B                  210
# define EXTRA_E_MD6_BAD_ELL                 211
# define EXTRA_E_MD6_BAD_p                   212
# define EXTRA_E_MD6_NULL_K                  213
# define EXTRA_E_MD6_NULL_Q                  214
# define EXTRA_E_MD6_NULL_C                  215
# define EXTRA_E_MD6_BAD_L                   216
# define EXTRA_E_MD6_BAD_r                   217
# define EXTRA_E_MD6_OUT_OF_MEMORY           218

#define MD6_REASONS                                                     \
    /* The following errors mimic the ones in external/md6/md6.h */     \
    { EXTRA_E_MD6_FAIL,                 "generic md6 failure" },        \
    { EXTRA_E_MD6_BADHASHLEN,           "bad md6 hash length (allowed values are 1 to 512)" }, \
    { EXTRA_E_MD6_NULLSTATE,            "null md6 state" },             \
    { EXTRA_E_MD6_BADKEYLEN,            "bad md6 key length" },         \
    { EXTRA_E_MD6_STATENOTINIT,         "md6 state not initialized" },  \
    { EXTRA_E_MD6_STACKUNDERFLOW,       "md6 stack underflows" },       \
    { EXTRA_E_MD6_STACKOVERFLOW,        "md6 stack overflow (message too long)" }, \
    { EXTRA_E_MD6_NULLDATA,             "null data pointer to md6" },   \
    { EXTRA_E_MD6_NULL_N,               "md6 compress: N is null" },    \
    { EXTRA_E_MD6_NULL_B,               "md6 standard compress: B is null" }, \
    { EXTRA_E_MD6_BAD_ELL,              "md6 standard compress: ell not in {0,255}" }, \
    { EXTRA_E_MD6_BAD_p,                "md6 standard compress: p<0 or p>b*w" }, \
    { EXTRA_E_MD6_NULL_K,               "md6 standard compress: K is null" }, \
    { EXTRA_E_MD6_NULL_Q,               "md6 standard compress: Q is null" }, \
    { EXTRA_E_MD6_NULL_C,               "md6 standard compress: C is null" }, \
    { EXTRA_E_MD6_BAD_L,                "md6 standard compress or init: L<0 or L>255" }, \
    { EXTRA_E_MD6_BAD_r,                "md6 compress or init: r<0 or r>255" }, \
    { EXTRA_E_MD6_OUT_OF_MEMORY,        "md6 compress: storage allocation failed" }
