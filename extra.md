# "extra", the provider with extra algorithm implementations

This provider includes a number of algorithms that didn't fit the criteria
for inclusion into the main OpenSSL source for diverse reasons, ranging from
having fallen so much out of favor that it isn't included even in the legacy
provider, to stuff that is too experimental, or needs to mature further
before inclusion in OpenSSL's official providers.

## Provider parameters

These parameters can be retrieved using [OSSL_PROVIDER_get_params(3)]:

-   "version" \<UTF8 string\>

    The version number of the provider.

-   "buildinfo" \<UTF8 string\>

    The build type as specified by [cmake].

-   "author" \<UTF8 string\>

    An identifier for the author of this provider.

## Currently included algorithms

### KDFs

-   [crypt](crypt.md)

### Hashes

-   [md6](md6.md)

## Usage example

This examples assumes that `extra.so` / `extra.dll` is located in the
current directory.

-   Listing this repository:

    ``` console
    $ openssl list -provider-path . -provider extra -providers -verbose
    Providers:
      extra
        version: 0.1
        build info: Debug
    ```

<!-- Links -->

[cmake]:
    <https://cmake.org>
[OSSL_PROVIDER_get_params(3)]:
    <https://www.openssl.org/docs/man3.0/man3/OSSL_PROVIDER_get_params.html>
