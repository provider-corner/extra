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

Included algorithms
-------------------

### KDFs

#### crypt, and implementation of **crypt(3)**

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

<!-- Logos and Badges -->

[github actions ci badge]:
    <https://github.com/provider-corner/extra/workflows/GitHub%20CI/badge.svg>
    "GitHub Actions CI Status"

[github actions ci]:
    <https://github.com/provider-corner/extra/actions?query=workflow%3A%22GitHub+CI%22>
    "GitHub Actions CI"

[github actions windows ci badge]:
    <https://github.com/provider-corner/extra/workflows/Windows%20GitHub%20CI/badge.svg>
    "GitHub Actions CI Status"

[github actions windows ci]:
    <https://github.com/provider-corner/extra/actions?query=workflow%3A%22Windows+GitHub+CI%22>
    "GitHub Actions CI"

