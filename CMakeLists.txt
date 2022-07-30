cmake_minimum_required(VERSION 3.12 FATAL_ERROR)
project(
  extra-provider
  VERSION 0.1
  DESCRIPTION "'extra' is the extra provider for OpenSSL 3, with stuff that doesn't exist there for diverse reasons, ranging from having fallen so much out of favor that it isn't included even in the legacy provider, to stuff that is too experimental, or needs to mature further before inclusion in OpenSSL's official providers."
  LANGUAGES C)
set(CMAKE_C_STANDARD 99)

include(CTest)

set(OPENSSL_USE_STATIC_LIBS TRUE)

add_subdirectory(libprov)

# For crypt.c, different libraries are needed depending on platform
# Only Windows uses OpenSSL::Crypto (support for Windows will disappear
# when OpenSSL doesn't support DES_crypt() any more)
if (DEFINED MSVC_VERSION)
  set(CRYPTLIB OpenSSL::Crypto)
elseif(NOT DEFINED APPLE)
  set(CRYPTLIB crypt)
endif()

include(libprov/cmake/provider.cmake)
build_provider(extra "extra.c;crypt.c" "libprov;${CRYPTLIB}")

# Testing
set(TEST_ENVIRONMENT
  OPENSSL_MODULES=${CMAKE_BINARY_DIR}
  OPENSSL_PROGRAM=${OPENSSL_PROGRAM}
  OPENSSL_CRYPTO_LIBRARY=${OPENSSL_CRYPTO_LIBRARY}
  SOURCEDIR=${CMAKE_CURRENT_SOURCE_DIR}
  PERL5LIB=${CMAKE_CURRENT_SOURCE_DIR}/t
  )

# Test with OpenSSL, using TAP
if (DEFINED MSVC_VERSION)
  set(PROVE prove.bat)
else()
  set(PROVE prove)
endif()
add_test(NAME openssl
  COMMAND ${PROVE} -PWrapOpenSSL ${CMAKE_CURRENT_SOURCE_DIR}/t)
set_tests_properties(openssl PROPERTIES ENVIRONMENT "${TEST_ENVIRONMENT}")
