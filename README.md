[![github actions ci badge]][github actions ci]
[![github actions windows ci badge]][github actions windows ci]

![CC-BY](https://i.creativecommons.org/l/by/4.0/80x15.png)

'Extra' provider
================

This is an extra provider for OpenSSL 3, with stuff that doesn't exist
there for diverse reasons, ranging from having fallen so much out of
favor that it isn't included even in the legacy provider, to stuff
that is too experimental, or needs to mature further before inclusion
in OpenSSL's official providers.

Essentially, if you really want to use some very old algorithm of some
sort, or want to play on the bleeding edge, or are in a rush trying
something new, chances are you'll find it here.

Building
--------

Building this provider requires [cmake](https://cmake.org) and a
building toolchain that it supports.

Simple configuration, for a system installation of OpenSSL 3:

    cmake -S . -B _build

If you have OpenSSL 3 installed somewhere else, do the following
instead, with `{path}` replaced with the directory of an OpenSSL 3
*installation*:

    cmake -DCMAKE_PREFIX_PATH={path} -S . -B _build

To build, do this:

    cmake --build _build

The result is `_build/extra.so` or `_build/extra.dll`.

Usage examples
--------------

Listing this repository:

``` console
$ openssl list -provider-path _build/ -provider extra -providers -verbose
Providers:
  extra
    version: 0.1
    build info: Debug
```

Properties
----------

All algorithms in this provider use the property "x.author" with an
identifier for the author of the code.  This can be used to fetch that
particular implementation, should there be several implementations of
the same algorithm present.

Included algorithms
-------------------

### KDFs

#### crypt, an implementation of **crypt(3)**

This KDF has the following output parameter:

-   "size", for which an unsigned integer is returned.  The size
    is always 13.

It also has the following input parameters:

-   "pass"; the value must be a string.
-   "salt"; the value must be a string with at least two ASCII
    characters.  Only the first two characters are used.

Example usage, using the `openssl` command:

``` console
$ openssl kdf -provider-path _build/ -provider extra -provider default -keylen 13 -kdfopt pass:12345 -kdfopt salt:xx -binary crypt
xxwddmriJc5TI
```

### Hashes

#### md6, a (forgotten?) SHA-3 contender

This hash algorithm has the following input / output parameter:

-   "size"; the value is an unsigned integer, and is the hash size in
    bytes.
-   "rounds"; the value is an integer, and is the number of rounds.
-   "mode"; the value is an integer, and is the mode parameter.

Defaults can be set for these parameters using environment variables:

-   `MD6_BITS`; the hash size in bits.
-   `MD6_ROUNDS`, the number of rounds.
-   `MD6_MODE`, the mode parameter.

##### md6 variants

There are a number of variants of this algorithm:

-   "md6-224"; md6 with 224-bit hash size.
-   "md6-256"; md6 with 256-bit hash size.
-   "md6-384"; md6 with 384-bit hash size.
-   "md6-512"; md6 with 512-bit hash size.

For all these variants, the hash size is hard coded and cannot be changed.

<!-- Logos and Badges -->

[github actions ci badge]:
    <https://github.com/provider-corner/extra/workflows/Linux%20%26%20MacOS%20GitHub%20CI/badge.svg>
    "GitHub Actions CI Status"

[github actions ci]:
    <https://github.com/provider-corner/extra/actions?query=workflow%3A%22Linux%20%26%20MacOS%20GitHub+CI%22>
    "GitHub Actions CI"

[github actions windows ci badge]:
    <https://github.com/provider-corner/extra/workflows/Windows%20GitHub%20CI/badge.svg>
    "GitHub Actions CI Status"

[github actions windows ci]:
    <https://github.com/provider-corner/extra/actions?query=workflow%3A%22Windows+GitHub+CI%22>
    "GitHub Actions CI"

