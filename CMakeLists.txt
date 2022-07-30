cmake_minimum_required(VERSION 3.12 FATAL_ERROR)
project(
  extra-provider
  VERSION 0.1
  DESCRIPTION "'extra' is the extra provider for OpenSSL 3, with stuff that doesn't exist there for diverse reasons, ranging from having fallen so much out of favor that it isn't included even in the legacy provider, to stuff that is too experimental, or needs to mature further before inclusion in OpenSSL's official providers."
  LANGUAGES C)
set(CMAKE_C_STANDARD 99)

include(CheckLibraryExists)
include(CheckFunctionExists)

enable_testing()

set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL 3.0 REQUIRED)

if (NOT DEFINED OPENSSL_ROOT_DIR)
  get_filename_component(OPENSSL_ROOT_DIR ${OPENSSL_INCLUDE_DIR} DIRECTORY)
endif()
find_program(OPENSSL_PROGRAM openssl
  PATHS ${OPENSSL_ROOT_DIR} PATH_SUFFIXES apps bin NO_DEFAULT_PATH)
message(STATUS "Found OpenSSL application: ${OPENSSL_PROGRAM}")

MESSAGE(DEBUG "OPENSSL_FOUND=${OPENSSL_FOUND}")
MESSAGE(DEBUG "OPENSSL_INCLUDE_DIR=${OPENSSL_INCLUDE_DIR}")
MESSAGE(DEBUG "OPENSSL_CRYPTO_LIBRARY=${OPENSSL_CRYPTO_LIBRARY}")
MESSAGE(DEBUG "OPENSSL_CRYPTO_LIBRARIES=${OPENSSL_CRYPTO_LIBRARIES}")
MESSAGE(DEBUG "OPENSSL_SSL_LIBRARY=${OPENSSL_SSL_LIBRARY}")
MESSAGE(DEBUG "OPENSSL_SSL_LIBRARIES=${OPENSSL_SSL_LIBRARIES}")
MESSAGE(DEBUG "OPENSSL_LIBRARIES=${OPENSSL_LIBRARIES}")
MESSAGE(DEBUG "OPENSSL_VERSION=${OPENSSL_VERSION}")
MESSAGE(DEBUG "OPENSSL_APPLINK_SOURCE=${OPENSSL_APPLINK_SOURCE}")

MESSAGE(DEBUG "OPENSSL_ROOT_DIR=${OPENSSL_ROOT_DIR}")
MESSAGE(DEBUG "OPENSSL_USE_STATIC_LIBS=${OPENSSL_USE_STATIC_LIBS}")
MESSAGE(DEBUG "OPENSSL_MSVC_STATIC_RT=${OPENSSL_MSVC_STATIC_RT}")

if (DEFINED MSVC_VERSION)
  # FindOpenSSL.cmake assumes http://www.slproweb.com/products/Win32OpenSSL.html
  # and gets it quite wrong when an install from OpenSSL source is present
  if (NOT EXISTS ${OPENSSL_CRYPTO_LIBRARIES})
    set(OPENSSL_CRYPTO_LIBRARIES
      ${OPENSSL_ROOT_DIR}/lib/libcrypto.lib)
  endif()
  if (NOT EXISTS ${OPENSSL_SSL_LIBRARIES})
    set(OPENSSL_SSL_LIBRARIES
      ${OPENSSL_ROOT_DIR}/lib/libssl.lib ${OPENSSL_CRYPTO_LIBRARIES})
  endif()
endif()

add_subdirectory(libprov)

# Provider module sources
add_library(extra MODULE extra.c
  crypt.c)

# For crypt.c, different libraries are needed depending on platform
# Only Windows uses OpenSSL::Crypto (support for Windows will disappear
# when OpenSSL doesn't support DES_crypt() any more)
if (DEFINED MSVC_VERSION)
  set(CRYPTLIB OpenSSL::Crypto)
elseif(NOT DEFINED APPLE)
  set(CRYPTLIB crypt)
endif()

# Putting together the provider module
set_target_properties(extra PROPERTIES
  PREFIX "" OUTPUT_NAME "extra" SUFFIX ${CMAKE_SHARED_LIBRARY_SUFFIX})
target_compile_definitions(extra PRIVATE
  VERSION="${CMAKE_PROJECT_VERSION}"
  BUILDTYPE="${CMAKE_BUILD_TYPE}"
  )
target_include_directories(extra PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(extra PRIVATE libprov ${CRYPTLIB})

# Testing
set(TEST_ENVIRONMENT
  OPENSSL_MODULES=${CMAKE_BINARY_DIR}
  OPENSSL_PROGRAM=${OPENSSL_PROGRAM}
  OPENSSL_CRYPTO_LIBRARY=${OPENSSL_CRYPTO_LIBRARY}
  SOURCEDIR=${CMAKE_CURRENT_SOURCE_DIR}
  PERL5LIB=${CMAKE_CURRENT_SOURCE_DIR}/t
  )

# Test with OpenSSL, using TAP
add_test(NAME openssl
  COMMAND prove -PWrapOpenSSL ${CMAKE_CURRENT_SOURCE_DIR}/t)
set_tests_properties(openssl PROPERTIES ENVIRONMENT "${TEST_ENVIRONMENT}")
