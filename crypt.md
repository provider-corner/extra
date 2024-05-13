<!--
SPDX-FileCopyrightText: 2023-2024 "extra" provider collective

SPDX-License-Identifier: LGPL-3.0-or-later
-->

# crypt, an implementation of **crypt(3)**

This implementation only supports the original [POSIX **crypt(3)**],
not the extended variants thereof.

## Algorithm Names

There is only one name for this implementation:

-   crypt

## Properties

The following properties can be used to distinguish this particular
implementation of the crypt KDF when fetching it with [EVP_KDF_fetch(3)]:

-   x.author=@levitte
-   provider=extra

## Algorithm parameters

These parameters can be retrieved using [EVP_KDF_gettable_params(3)] and
[EVP_KDF_get_params(3)]:

-   "size" \<unsigned integer\>

    The maximum size of the resulting key.  Because the resulting key is
    always in ASCII form, this size includes the terminating NUL byte.

    The function [EVP_KDF_get_kdf_size(3)] uses this parameter implicitly.

## Algorithm context parameters

These parameters can be retrieved using [EVP_KDF_CTX_gettable_params(3)] and
[EVP_KDF_CTX_get_params(3)]:

-   "pass" \<UTF8 string\>

    The passphrase to derive a key from.

-   "salt" \<UTF8 string\>

    The salt to use when deriving the key.  This string must be at least two
    characters long.  Only the first two characters will be used.

    The Unix passwd program used to pass the username as salt when deriving
    a key from the user's password.

## Environment

This implementation doesn't use any environment variables.

## Example command line usage

These examples all assume that `extra.so` / `extra.dll` is located in
the current directory.

``` console
$ openssl kdf -provider-path . -provider extra \
    -keylen 13 -kdfopt pass:'testing' -kdfopt salt:'ef' -binary crypt
efGnQx2725bI2
```

<!-- Links -->

[POSIX **crypt(3)**]:
    <https://pubs.opengroup.org/onlinepubs/9699919799/functions/crypt.html>
[EVP_KDF_fetch(3)]:
    <https://www.openssl.org/docs/man3.0/man3/EVP_KDF_fetch.html>

[EVP_KDF_gettable_params(3)]:
    <https://www.openssl.org/docs/man3.0/man3/EVP_KDF_gettable_params.html>
[EVP_KDF_get_params(3)]:
    <https://www.openssl.org/docs/man3.0/man3/EVP_KDF_get_params.html>
[EVP_KDF_get_kdf_size(3)]:
    <https://www.openssl.org/docs/man3.0/man3/EVP_KDF_get_kdf_size.html>
[EVP_KDF_CTX_gettable_params(3)]:
    <https://www.openssl.org/docs/man3.0/man3/EVP_KDF_CTX_gettable_params.html>
[EVP_KDF_CTX_get_params(3)]:
    <https://www.openssl.org/docs/man3.0/man3/EVP_KDF_CTX_get_params.html>
