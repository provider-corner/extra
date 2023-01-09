# md6, a (forgotten?) SHA-3 contender

This implements md6 for OpenSSL 3, following the [md6 report] and
using an the original optimized implementation.

This implementation doesn't support keyed hashes (yet).

## Algorithm Names

The following names can be used with [EVP_MD_fetch(3)]

-   md6

    This is the main unqualified algorithm name.
    
-   md6-128
-   md6-224
-   md6-256
-   md6-384
-   md6-512

    These are variants of md6, qualified with the hash output size
    expressed in bits.

## Properties

The following properties can be used to distinguish this particular
implementation of md6 when fetching it with [EVP_MD_fetch(3)]:

-   x.author=@levitte
-   provider=extra

## Algorithm parameters

These parameters can be retrieved using [EVP_MD_gettable_params(3)] and
[EVP_MD_get_params(3)]:

-   "size" \<unsigned integer\>

    The standard hash output size, expressed in number of bytes.
    
    For the "md6" algorithm name, this size is unset (zero) unless the
    environment variable `MD6_BITS` is set, see the description of
    [Environment] below.

    For the "md6" algorithm variants that include a hash output size
    in bits, the number received with this parameter is calculated
    from that number of bits.

    The function [EVP_MD_get_size(3)] uses this parameter implicitly.

-   "rounds" \<unsigned integer\>

    The standard number of rounds, calculated from the standard hash
    output size.
    
    This is called *r* in the [md6 report].

-   "mode" \<unsigned integer\>

    The md6 operation mode.

    This is called *L* in the [md6 report].

## Algorithm context parameters

These parameters can be retrieved using [EVP_MD_CTX_gettable_params(3)],
[EVP_MD_CTX_get_params(3)], [EVP_MD_CTX_settable_params(3)], and
[EVP_MD_CTX_set_params(3)].

-   "size" \<unsigned integer\>

    The hash output size, expressed in number of bytes.
    
    For the "md6" algorithm variants that include a hash output size
    in bits, the number received with this parameter is calculated
    from that number of bits and cannot be changed.

    The function [EVP_MD_CTX_get_size(3)] uses this parameter implicitly.

-   "rounds" \<unsigned integer\>

    The number of rounds.
    
    This is called *r* in the [md6 report].

-   "mode" \<unsigned integer\>

    The md6 operation mode.

    This is called *L* in the [md6 report].

## Environment

Defaults can be set for these parameters using environment variables:

-   `MD6_BITS`

    The hash output size in bits.

    This is called *d* in the [md6 report].

-   `MD6_ROUNDS`

    The number of rounds.

    This is called *r* in the [md6 report].

-   `MD6_MODE`

    The mode parameter.

    This is called *L* in the [md6 report].

## Example command line usage

These examples all assume that `extra.so` / `extra.dll` is located in
the current directory.

-   Using the md6 variants with explicit hash output size and
    modified number of rounds:

    ``` console
    $ echo -n 'abc' \
      | MD6_ROUNDS=5 openssl dgst \
          -provider-path . -provider extra -md6-256
    md6-256(stdin)= 8854c14dc284f840ed71ad7ba542855ce189633e48c797a55121a746be48cec8
    ```

-   Same as above, but setting the hash output size with `MD6_BITS`:

    ``` console
    $ echo -n 'abc' \
      | MD6_BITS=256 MD6_ROUNDS=5 openssl dgst \
          -provider-path . -provider extra -md6
    md6(stdin)= 8854c14dc284f840ed71ad7ba542855ce189633e48c797a55121a746be48cec8
    ```

<!-- Links -->

[md6 report]:
    ./external/md6_report.pdf
    "Copy of http://www.jayantkrish.com/papers/md6_report.pdf"
[EVP_MD_fetch(3)]:
    <https://www.openssl.org/docs/man3.0/man3/EVP_MD_fetch.html>

[EVP_MD_gettable_params(3)]:
    <https://www.openssl.org/docs/man3.0/man3/EVP_MD_gettable_params.html>
[EVP_MD_get_params(3)]:
    <https://www.openssl.org/docs/man3.0/man3/EVP_MD_get_params.html>
[EVP_MD_get_size(3)]:
    <https://www.openssl.org/docs/man3.0/man3/EVP_MD_get_kdf_size.html>
[EVP_MD_CTX_gettable_params(3)]:
    <https://www.openssl.org/docs/man3.0/man3/EVP_MD_CTX_gettable_params.html>
[EVP_MD_CTX_get_params(3)]:
    <https://www.openssl.org/docs/man3.0/man3/EVP_MD_CTX_get_params.html>
[EVP_MD_CTX_settable_params(3)]:
    <https://www.openssl.org/docs/man3.0/man3/EVP_MD_CTX_settable_params.html>
[EVP_MD_CTX_set_params(3)]:
    <https://www.openssl.org/docs/man3.0/man3/EVP_MD_CTX_set_params.html>
[EVP_MD_CTX_get_size(3)]:
    <https://www.openssl.org/docs/man3.0/man3/EVP_MD_get_kdf_size.html>

[Environment]: #environment
