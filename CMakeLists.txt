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
if (DEFINED MSVC)
  set(CRYPTLIB OpenSSL::Crypto)
elseif(NOT DEFINED APPLE)
  set(CRYPTLIB crypt)
endif()

include(libprov/cmake/provider.cmake)
setup_provider_openssl()

set(extra_source
    extra.c
    # Implement The "crypt" KDF, using libcrypt or OpenSSL's DES_crypt()
    crypt.c
    # Implement MD6, with help from the reference implementation
    md6.c
    external/md6/md6_mode.c
    external/md6/md6_compress.c)
build_provider(extra "${extra_source}" "libprov;${CRYPTLIB}")

# Testing
if (DEFINED MSVC)
  # This is frustrating!  I've tried guessing at all sorts of variables,
  # as well as getting the target property LIBRARY_OUTPUT_DIRECTORY using
  # get_target_property() as well as generator expressions, but to not avail.
  # So for now, the MODULES path gets hardcoded from observed builds.
  if (NOT CMAKE_BUILD_TYPE)
    # From observation, it seems that Debug is the default
    set(EXTRA_MODULE_DIRECTORY "${CMAKE_BINARY_DIR}/Debug")
  else()
    set(EXTRA_MODULE_DIRECTORY "${CMAKE_BINARY_DIR}/${CMAKE_BUILD_TYPE}")
  endif()
else()
  set(EXTRA_MODULE_DIRECTORY "${CMAKE_BINARY_DIR}")
endif()
message(STATUS "Determined the Extra provider location to '${EXTRA_MODULE_DIRECTORY}'")

set(TEST_ENVIRONMENT
  OPENSSL_MODULES=${EXTRA_MODULE_DIRECTORY}
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

# Installing
execute_process(
  COMMAND ${OPENSSL_PROGRAM} info -modulesdir
  OUTPUT_VARIABLE OPENSSL_MODULES_DIR
)
string(STRIP "${OPENSSL_MODULES_DIR}" OPENSSL_MODULES_DIR)
message(STATUS "Will install in ${OPENSSL_MODULES_DIR}")
install(TARGETS extra DESTINATION ${OPENSSL_MODULES_DIR})
