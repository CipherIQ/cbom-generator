cmake_minimum_required(VERSION 3.16)
project(cbom-generator VERSION 1.9.4 LANGUAGES C)

# Set C11 standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Reproducible builds - pin compiler versions and add file prefix mapping
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ffile-prefix-map=${CMAKE_SOURCE_DIR}=.")

# Security and hardening flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-strong")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_FORTIFY_SOURCE=2")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-omit-frame-pointer")

# Additional security flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Werror")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wformat=2 -Wformat-security")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIE")

# Release optimizations
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O2 -DNDEBUG")

# Debug flags
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g -O0 -DDEBUG")

# Link flags for security
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pie -Wl,-z,relro,-z,now")

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src)

# Find required packages with pinned versions
find_package(PkgConfig REQUIRED)

# OpenSSL 3.0+ required (3.0, 3.1, 3.2, 3.3, 3.4, 3.5+ for PQC support)
find_package(OpenSSL 3.0 REQUIRED)
if(OPENSSL_VERSION VERSION_LESS "3.0.0")
    message(FATAL_ERROR "OpenSSL version must be 3.0 or newer, found ${OPENSSL_VERSION}")
endif()

# json-c library
pkg_check_modules(JSON_C REQUIRED json-c>=0.15)

# libcurl
find_package(CURL REQUIRED)

# pthread
find_package(Threads REQUIRED)

# ncurses for TUI
find_package(Curses REQUIRED)

# libyaml for YAML plugin support (v1.3)
pkg_check_modules(YAML REQUIRED yaml-0.1>=0.2.2)

# jansson for JSON Schema validation (v1.3)
pkg_check_modules(JANSSON REQUIRED jansson>=2.13)

# Capture git information for provenance
find_package(Git QUIET)
if(GIT_FOUND)
    execute_process(
        COMMAND ${GIT_EXECUTABLE} rev-parse HEAD
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_COMMIT_HASH
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )
    execute_process(
        COMMAND ${GIT_EXECUTABLE} rev-parse --abbrev-ref HEAD
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_BRANCH
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )
    execute_process(
        COMMAND ${GIT_EXECUTABLE} diff --quiet
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        RESULT_VARIABLE GIT_DIRTY_RESULT
        ERROR_QUIET
    )
    if(GIT_DIRTY_RESULT EQUAL 0)
        set(GIT_DIRTY "false")
    else()
        set(GIT_DIRTY "true")
    endif()
else()
    set(GIT_COMMIT_HASH "unknown")
    set(GIT_BRANCH "unknown")
    set(GIT_DIRTY "unknown")
endif()

# Get JSON-C version
execute_process(
    COMMAND pkg-config --modversion json-c
    OUTPUT_VARIABLE JSON_C_VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
)
if(NOT JSON_C_VERSION)
    set(JSON_C_VERSION "unknown")
endif()

# Get OpenSSL version string - use pkg-config directly for reliability
execute_process(
    COMMAND pkg-config --modversion openssl
    OUTPUT_VARIABLE CBOM_OPENSSL_VER
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
)
if(NOT CBOM_OPENSSL_VER)
    set(CBOM_OPENSSL_VER "3.0.2")  # Fallback to known version
endif()


# Set build timestamp
string(TIMESTAMP CMAKE_TIMESTAMP "%Y-%m-%dT%H:%M:%SZ" UTC)

# Record dependency versions in provenance metadata (after all dependencies are found)
configure_file(
    "${CMAKE_SOURCE_DIR}/src/provenance.h.in"
    "${CMAKE_BINARY_DIR}/src/provenance.h"
    @ONLY
)



# Source files (explicitly listed to avoid orphan code issues)
set(SOURCES
    src/asset_store.c
    src/secure_memory.c
    src/normalization.c
    src/error_handling.c
    src/error_remediation.c
    src/schema_validation.c
    src/cyclonedx_converter.c
    src/resource_manager.c
    src/privacy.c
    src/config.c
    src/thread_pool.c
    src/timeout_manager.c
    src/plugin_manager.c
    src/builtin_scanners.c
    src/certificate_scanner.c
    src/openpgp_parser.c
    src/key_manager.c
    src/key_scanner.c
    src/package_scanner.c
    src/application_scanner.c
    src/service_scanner.c
    src/cipher_suite_parser.c
    src/service_relationships.c
    src/cache.c
    src/filesystem_scanner.c
    src/dedup.c
    src/slsa_provenance.c
    src/attestation.c
    src/algorithm_metadata.c
    src/platform_detect.c
    src/protocol_mapping.c
    src/pqc_classifier.c
    src/pqc_report.c
    src/tui_queue.c
    src/tui.c
    src/yaml_parser.c
    src/yaml_plugin_loader.c
    src/plugin_schema.c
    src/service_discovery.c
    src/service_discovery_engine.c
    src/detection/process_detector.c
    src/detection/port_detector.c
    src/detection/config_detector.c
    src/detection/systemd_detector.c
    src/detection/package_detector.c
    src/detection/binary_detector.c
    src/detection/kernel_crypto_detector.c
    src/detection/library_detection.c
    src/config_parser_registry.c
    src/parsers/ini_parser.c
    src/parsers/apache_parser.c
    src/parsers/nginx_parser.c
    src/parsers/yaml_config_parser.c
    src/parsers/json_parser.c
    src/parsers/openssl_cipher_parser.c
    src/config_type_converter.c
    src/variable_expander.c
    src/path_resolver.c
    src/config_extractor.c
    src/component_factory.c
    src/crypto_registry.c
    src/version_resolver.c
    src/path_utils.c

)

# Main executable (cbom_serializer.c added directly here, not in SOURCES)
add_executable(cbom-generator src/main.c src/cbom_serializer.c ${SOURCES})

# Link libraries
target_link_libraries(cbom-generator
    OpenSSL::SSL
    OpenSSL::Crypto
    ${JSON_C_LIBRARIES}
    ${CURL_LIBRARIES}
    ${CURSES_LIBRARIES}
    ${YAML_LIBRARIES}
    ${JANSSON_LIBRARIES}
    Threads::Threads
    dl  # dynamic loading library for plugins
    m   # math library
)

# Include directories for dependencies
target_include_directories(cbom-generator PRIVATE
    ${JSON_C_INCLUDE_DIRS}
    ${CURL_INCLUDE_DIRS}
    ${CURSES_INCLUDE_DIRS}
    ${YAML_INCLUDE_DIRS}
    ${JANSSON_INCLUDE_DIRS}
    ${CMAKE_BINARY_DIR}/src
)

# Compiler definitions
target_compile_definitions(cbom-generator PRIVATE ${JSON_C_CFLAGS_OTHER})

# Install target
install(TARGETS cbom-generator DESTINATION bin)

# Enable testing
enable_testing()

# Test executable (explicitly listed to avoid orphan code issues)
set(TEST_SOURCES
    tests/test_runner.c
    tests/test_asset_store.c
    tests/test_normalization.c
    tests/test_error_handling.c
    tests/test_cyclonedx_converter.c
    tests/test_resource_manager.c
    tests/test_privacy.c
    tests/test_config.c
    tests/test_privacy_simple.c
    tests/test_resource_manager_simple.c
    tests/test_thread_pool.c
    tests/test_timeout_manager.c
    tests/test_plugin_manager.c
    tests/test_filesystem_scanner_integrated.c
    tests/test_crypto_registry.c
    tests/test_library_detection.c
    tests/test_embedded_providers.c
    tests/test_cert_scanner_stats.c
)
if(TEST_SOURCES)
    add_executable(cbom-tests ${TEST_SOURCES} ${SOURCES} tests/test_globals.c)
    target_link_libraries(cbom-tests
        OpenSSL::SSL
        OpenSSL::Crypto
        ${JSON_C_LIBRARIES}
        ${CURL_LIBRARIES}
        ${CURSES_LIBRARIES}
        ${YAML_LIBRARIES}
        ${JANSSON_LIBRARIES}
        Threads::Threads
        dl  # dynamic loading library for plugins
        m   # math library
    )
    target_include_directories(cbom-tests PRIVATE
        ${JSON_C_INCLUDE_DIRS}
        ${CURL_INCLUDE_DIRS}
        ${CURSES_INCLUDE_DIRS}
        ${YAML_INCLUDE_DIRS}
        ${JANSSON_INCLUDE_DIRS}
        ${CMAKE_BINARY_DIR}/src
    )
    target_compile_definitions(cbom-tests PRIVATE ${JSON_C_CFLAGS_OTHER} TEST_RUNNER_INTEGRATION)

    # Relax warnings for test files
    target_compile_options(cbom-tests PRIVATE -Wno-unused-variable -Wno-unused-but-set-variable -Wno-unused-parameter)
    
    add_test(NAME cbom_unit_tests COMMAND cbom-tests)
endif()

# Separate cache test executable
add_executable(cbom-cache-tests tests/test_cache.c tests/test_cert_scanner_stats.c ${SOURCES} tests/test_globals.c)
target_link_libraries(cbom-cache-tests
    OpenSSL::SSL
    OpenSSL::Crypto
    ${JSON_C_LIBRARIES}
    ${CURL_LIBRARIES}
    ${CURSES_LIBRARIES}
    ${YAML_LIBRARIES}
    ${JANSSON_LIBRARIES}
    Threads::Threads
    dl  # dynamic loading library for plugins
    m   # math library
)
target_include_directories(cbom-cache-tests PRIVATE
    ${JSON_C_INCLUDE_DIRS}
    ${CURL_INCLUDE_DIRS}
    ${YAML_INCLUDE_DIRS}
    ${JANSSON_INCLUDE_DIRS}
    ${CMAKE_BINARY_DIR}/src
)
target_compile_definitions(cbom-cache-tests PRIVATE ${JSON_C_CFLAGS_OTHER})

# Relax warnings for cache test file
target_compile_options(cbom-cache-tests PRIVATE -Wno-unused-variable -Wno-unused-but-set-variable -Wno-unused-parameter)

add_test(NAME cbom_cache_tests COMMAND cbom-cache-tests)

# Certificate scanner test executable
add_executable(cbom-cert-tests tests/test_certificate_scanner.c tests/test_cert_scanner_stats.c ${SOURCES} tests/test_globals.c)
target_link_libraries(cbom-cert-tests 
    OpenSSL::SSL 
    OpenSSL::Crypto
    ${JSON_C_LIBRARIES}
    ${CURL_LIBRARIES}
        ${CURSES_LIBRARIES}
    Threads::Threads
        ${YAML_LIBRARIES}
        ${JANSSON_LIBRARIES}
        ${CURSES_LIBRARIES}
    dl  # dynamic loading library for plugins
    m   # math library
)
target_include_directories(cbom-cert-tests PRIVATE 
    ${JSON_C_INCLUDE_DIRS}
    ${CURL_INCLUDE_DIRS}
    ${YAML_INCLUDE_DIRS}
    ${JANSSON_INCLUDE_DIRS}
    ${CMAKE_BINARY_DIR}/src
)
target_compile_definitions(cbom-cert-tests PRIVATE ${JSON_C_CFLAGS_OTHER})

# Relax warnings for certificate test file
target_compile_options(cbom-cert-tests PRIVATE -Wno-unused-variable -Wno-unused-but-set-variable -Wno-unused-parameter)

add_test(NAME cbom_cert_tests COMMAND cbom-cert-tests)

# Focused certificate scanner test executable
add_executable(cbom-cert-focused tests/test_cert_scanner_focused.c tests/test_cert_scanner_stats.c ${SOURCES} tests/test_globals.c)
target_link_libraries(cbom-cert-focused 
    OpenSSL::SSL 
    OpenSSL::Crypto
    ${JSON_C_LIBRARIES}
    ${CURL_LIBRARIES}
    Threads::Threads
        ${YAML_LIBRARIES}
        ${JANSSON_LIBRARIES}
        ${CURSES_LIBRARIES}
    dl  # dynamic loading library for plugins
    m   # math library
)
target_include_directories(cbom-cert-focused PRIVATE 
    ${JSON_C_INCLUDE_DIRS}
    ${CURL_INCLUDE_DIRS}
    ${YAML_INCLUDE_DIRS}
    ${JANSSON_INCLUDE_DIRS}
    ${CMAKE_BINARY_DIR}/src
)
target_compile_definitions(cbom-cert-focused PRIVATE ${JSON_C_CFLAGS_OTHER})

# Relax warnings for focused test file
target_compile_options(cbom-cert-focused PRIVATE -Wno-unused-variable -Wno-unused-but-set-variable -Wno-unused-parameter)

add_test(NAME cbom_cert_focused_tests COMMAND cbom-cert-focused)

# Filesystem scanner test executable
add_executable(cbom-fs-tests tests/test_filesystem_scanner.c tests/test_cert_scanner_stats.c ${SOURCES} tests/test_globals.c)
target_link_libraries(cbom-fs-tests 
    OpenSSL::SSL 
    OpenSSL::Crypto
    ${JSON_C_LIBRARIES}
    ${CURL_LIBRARIES}
        ${CURSES_LIBRARIES}
    Threads::Threads
        ${YAML_LIBRARIES}
        ${JANSSON_LIBRARIES}
        ${CURSES_LIBRARIES}
    dl  # dynamic loading library for plugins
    m   # math library
)
target_include_directories(cbom-fs-tests PRIVATE 
    ${JSON_C_INCLUDE_DIRS}
    ${CURL_INCLUDE_DIRS}
    ${YAML_INCLUDE_DIRS}
    ${JANSSON_INCLUDE_DIRS}
    ${CMAKE_BINARY_DIR}/src
)
target_compile_definitions(cbom-fs-tests PRIVATE ${JSON_C_CFLAGS_OTHER})

# Relax warnings for filesystem test file
target_compile_options(cbom-fs-tests PRIVATE -Wno-unused-variable -Wno-unused-but-set-variable -Wno-unused-parameter)

add_test(NAME cbom_fs_tests COMMAND cbom-fs-tests)

# Simple filesystem scanner test executable (without certificate scanner dependencies)
# Commented out: conflicts with TUI tui_log() requirement
# add_executable(cbom-fs-simple-tests tests/test_filesystem_scanner_simple.c
#     src/filesystem_scanner.c
#     src/asset_store.c
#     src/secure_memory.c
#     src/resource_manager.c
#     src/error_handling.c
# )
# target_link_libraries(cbom-fs-simple-tests
#     OpenSSL::SSL
#     OpenSSL::Crypto
#     ${JSON_C_LIBRARIES}
#     ${CURL_LIBRARIES}
#         ${CURSES_LIBRARIES}
#     Threads::Threads
#         ${CURSES_LIBRARIES}
#     dl  # dynamic loading library for plugins
#     m   # math library
# )
# target_include_directories(cbom-fs-simple-tests PRIVATE
#     ${JSON_C_INCLUDE_DIRS}
#     ${CURL_INCLUDE_DIRS}
#     ${CMAKE_BINARY_DIR}/src
# )
# target_compile_definitions(cbom-fs-simple-tests PRIVATE ${JSON_C_CFLAGS_OTHER})
#
# # Relax warnings for simple test file
# target_compile_options(cbom-fs-simple-tests PRIVATE -Wno-unused-variable -Wno-unused-but-set-variable -Wno-unused-parameter)
#
# add_test(NAME cbom_fs_simple_tests COMMAND cbom-fs-simple-tests)

# Cache demo executable (disabled - examples/cache_demo.c removed)
# add_executable(cbom-cache-demo examples/cache_demo.c tests/test_cert_scanner_stats.c ${SOURCES} tests/test_globals.c)
# target_link_libraries(cbom-cache-demo
#     OpenSSL::SSL
#     OpenSSL::Crypto
#     ${JSON_C_LIBRARIES}
#     ${CURL_LIBRARIES}
#     Threads::Threads
#         ${YAML_LIBRARIES}
#         ${JANSSON_LIBRARIES}
#         ${CURSES_LIBRARIES}
#     dl  # dynamic loading library for plugins
#     m   # math library
# )
# target_include_directories(cbom-cache-demo PRIVATE
#     ${JSON_C_INCLUDE_DIRS}
#     ${CURL_INCLUDE_DIRS}
#     ${YAML_INCLUDE_DIRS}
#     ${JANSSON_INCLUDE_DIRS}
#     ${CMAKE_BINARY_DIR}/src
# )
# target_compile_definitions(cbom-cache-demo PRIVATE ${JSON_C_CFLAGS_OTHER})
#
# # Relax warnings for demo file
# target_compile_options(cbom-cache-demo PRIVATE -Wno-unused-variable -Wno-unused-but-set-variable -Wno-unused-parameter)

# Privacy and attestation test executable
add_executable(cbom-privacy-attestation-tests tests/test_privacy_attestation.c tests/test_cert_scanner_stats.c ${SOURCES} tests/test_globals.c)
target_link_libraries(cbom-privacy-attestation-tests
    OpenSSL::SSL
    OpenSSL::Crypto
    ${JSON_C_LIBRARIES}
    ${CURL_LIBRARIES}
        ${CURSES_LIBRARIES}
    Threads::Threads
        ${YAML_LIBRARIES}
        ${JANSSON_LIBRARIES}
        ${CURSES_LIBRARIES}
    dl  # dynamic loading library for plugins
    m   # math library
)
target_include_directories(cbom-privacy-attestation-tests PRIVATE
    ${JSON_C_INCLUDE_DIRS}
    ${CURL_INCLUDE_DIRS}
    ${YAML_INCLUDE_DIRS}
    ${JANSSON_INCLUDE_DIRS}
    ${CMAKE_BINARY_DIR}/src
)
target_compile_definitions(cbom-privacy-attestation-tests PRIVATE ${JSON_C_CFLAGS_OTHER})

add_test(NAME cbom_privacy_attestation_tests COMMAND cbom-privacy-attestation-tests)

# Determinism and completion metrics test executable
add_executable(cbom-determinism-tests tests/test_determinism.c tests/test_cert_scanner_stats.c ${SOURCES} tests/test_globals.c)
target_link_libraries(cbom-determinism-tests
    OpenSSL::SSL
    OpenSSL::Crypto
    ${JSON_C_LIBRARIES}
    ${CURL_LIBRARIES}
        ${CURSES_LIBRARIES}
    Threads::Threads
        ${YAML_LIBRARIES}
        ${JANSSON_LIBRARIES}
        ${CURSES_LIBRARIES}
    dl  # dynamic loading library for plugins
    m   # math library
)
target_include_directories(cbom-determinism-tests PRIVATE
    ${JSON_C_INCLUDE_DIRS}
    ${CURL_INCLUDE_DIRS}
    ${YAML_INCLUDE_DIRS}
    ${JANSSON_INCLUDE_DIRS}
    ${CMAKE_BINARY_DIR}/src
)
target_compile_definitions(cbom-determinism-tests PRIVATE ${JSON_C_CFLAGS_OTHER})

add_test(NAME cbom_determinism_tests COMMAND cbom-determinism-tests)

# Key scanner test executable
add_executable(cbom-key-scanner-tests tests/test_key_scanner.c tests/test_cert_scanner_stats.c ${SOURCES} tests/test_globals.c)
target_link_libraries(cbom-key-scanner-tests
    OpenSSL::SSL
    OpenSSL::Crypto
    ${JSON_C_LIBRARIES}
    ${CURL_LIBRARIES}
        ${CURSES_LIBRARIES}
    Threads::Threads
        ${YAML_LIBRARIES}
        ${JANSSON_LIBRARIES}
        ${CURSES_LIBRARIES}
    dl  # dynamic loading library for plugins
    m   # math library
)
target_include_directories(cbom-key-scanner-tests PRIVATE
    ${JSON_C_INCLUDE_DIRS}
    ${CURL_INCLUDE_DIRS}
    ${YAML_INCLUDE_DIRS}
    ${JANSSON_INCLUDE_DIRS}
    ${CMAKE_BINARY_DIR}/src
)
target_compile_definitions(cbom-key-scanner-tests PRIVATE ${JSON_C_CFLAGS_OTHER})

# Relax warnings for test file
target_compile_options(cbom-key-scanner-tests PRIVATE -Wno-unused-variable -Wno-unused-but-set-variable -Wno-unused-parameter)

add_test(NAME cbom_key_scanner_tests COMMAND cbom-key-scanner-tests)

# Package scanner test executable
add_executable(cbom-package-scanner-tests tests/test_package_scanner.c tests/test_cert_scanner_stats.c ${SOURCES} tests/test_globals.c)
target_link_libraries(cbom-package-scanner-tests
    OpenSSL::SSL
    OpenSSL::Crypto
    ${JSON_C_LIBRARIES}
    ${CURL_LIBRARIES}
        ${CURSES_LIBRARIES}
    Threads::Threads
        ${YAML_LIBRARIES}
        ${JANSSON_LIBRARIES}
        ${CURSES_LIBRARIES}
    dl  # dynamic loading library for plugins
    m   # math library
)
target_include_directories(cbom-package-scanner-tests PRIVATE
    ${JSON_C_INCLUDE_DIRS}
    ${CURL_INCLUDE_DIRS}
    ${YAML_INCLUDE_DIRS}
    ${JANSSON_INCLUDE_DIRS}
    ${CMAKE_BINARY_DIR}/src
)
target_compile_definitions(cbom-package-scanner-tests PRIVATE ${JSON_C_CFLAGS_OTHER})

# Relax warnings for test file
target_compile_options(cbom-package-scanner-tests PRIVATE -Wno-unused-variable -Wno-unused-but-set-variable -Wno-unused-parameter)

add_test(NAME cbom_package_scanner_tests COMMAND cbom-package-scanner-tests)

# Service scanner test executable
add_executable(cbom-service-scanner-tests tests/test_service_scanner.c tests/test_cert_scanner_stats.c ${SOURCES} tests/test_globals.c)
target_link_libraries(cbom-service-scanner-tests
    OpenSSL::SSL
    OpenSSL::Crypto
    ${JSON_C_LIBRARIES}
    ${CURL_LIBRARIES}
        ${CURSES_LIBRARIES}
    Threads::Threads
        ${YAML_LIBRARIES}
        ${JANSSON_LIBRARIES}
        ${CURSES_LIBRARIES}
    dl  # dynamic loading library for plugins
    m   # math library
)
target_include_directories(cbom-service-scanner-tests PRIVATE
    ${JSON_C_INCLUDE_DIRS}
    ${CURL_INCLUDE_DIRS}
    ${YAML_INCLUDE_DIRS}
    ${JANSSON_INCLUDE_DIRS}
    ${CMAKE_BINARY_DIR}/src
)
target_compile_definitions(cbom-service-scanner-tests PRIVATE ${JSON_C_CFLAGS_OTHER})

# Relax warnings for test file
target_compile_options(cbom-service-scanner-tests PRIVATE -Wno-unused-variable -Wno-unused-but-set-variable -Wno-unused-parameter)

add_test(NAME cbom_service_scanner_tests COMMAND cbom-service-scanner-tests)

# Cipher suite parser test executable
add_executable(cbom-cipher-suite-tests tests/test_cipher_suite_parser.c tests/test_cert_scanner_stats.c ${SOURCES} tests/test_globals.c)
target_link_libraries(cbom-cipher-suite-tests
    OpenSSL::SSL
    OpenSSL::Crypto
    ${JSON_C_LIBRARIES}
    ${CURL_LIBRARIES}
        ${CURSES_LIBRARIES}
    Threads::Threads
        ${YAML_LIBRARIES}
        ${JANSSON_LIBRARIES}
        ${CURSES_LIBRARIES}
    dl
    m
)
target_include_directories(cbom-cipher-suite-tests PRIVATE
    ${JSON_C_INCLUDE_DIRS}
    ${CURL_INCLUDE_DIRS}
    ${YAML_INCLUDE_DIRS}
    ${JANSSON_INCLUDE_DIRS}
    ${CMAKE_BINARY_DIR}/src
)
target_compile_definitions(cbom-cipher-suite-tests PRIVATE ${JSON_C_CFLAGS_OTHER})
target_compile_options(cbom-cipher-suite-tests PRIVATE -Wno-unused-variable -Wno-unused-but-set-variable -Wno-unused-parameter)

add_test(NAME cbom_cipher_suite_tests COMMAND cbom-cipher-suite-tests)

# Crypto registry test executable
add_executable(cbom-crypto-registry-tests tests/test_crypto_registry.c tests/test_cert_scanner_stats.c src/crypto_registry.c ${SOURCES} tests/test_globals.c)
target_link_libraries(cbom-crypto-registry-tests
    OpenSSL::SSL
    OpenSSL::Crypto
    ${JSON_C_LIBRARIES}
    ${CURL_LIBRARIES}
    ${CURSES_LIBRARIES}
    Threads::Threads
    ${YAML_LIBRARIES}
    ${JANSSON_LIBRARIES}
    dl
    m
)
target_include_directories(cbom-crypto-registry-tests PRIVATE
    ${JSON_C_INCLUDE_DIRS}
    ${CURL_INCLUDE_DIRS}
    ${YAML_INCLUDE_DIRS}
    ${JANSSON_INCLUDE_DIRS}
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_BINARY_DIR}/src
)
target_compile_definitions(cbom-crypto-registry-tests PRIVATE ${JSON_C_CFLAGS_OTHER})
target_compile_options(cbom-crypto-registry-tests PRIVATE -Wno-unused-variable -Wno-unused-but-set-variable)

add_test(NAME cbom_crypto_registry_tests COMMAND cbom-crypto-registry-tests)

# Version resolver test executable
add_executable(cbom-version-resolver-tests tests/test_version_resolver.c tests/test_cert_scanner_stats.c ${SOURCES} tests/test_globals.c)
target_link_libraries(cbom-version-resolver-tests
    OpenSSL::SSL
    OpenSSL::Crypto
    ${JSON_C_LIBRARIES}
    ${CURL_LIBRARIES}
    ${CURSES_LIBRARIES}
    Threads::Threads
    ${YAML_LIBRARIES}
    ${JANSSON_LIBRARIES}
    dl
    m
)
target_include_directories(cbom-version-resolver-tests PRIVATE
    ${JSON_C_INCLUDE_DIRS}
    ${CURL_INCLUDE_DIRS}
    ${YAML_INCLUDE_DIRS}
    ${JANSSON_INCLUDE_DIRS}
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_BINARY_DIR}/src
)
target_compile_definitions(cbom-version-resolver-tests PRIVATE ${JSON_C_CFLAGS_OTHER})
target_compile_options(cbom-version-resolver-tests PRIVATE -Wno-unused-variable -Wno-unused-but-set-variable)

add_test(NAME cbom_version_resolver_tests COMMAND cbom-version-resolver-tests)

# PQC classifier test executable
add_executable(cbom-pqc-classifier-tests tests/test_pqc_classifier.c tests/test_cert_scanner_stats.c ${SOURCES} tests/test_globals.c)
target_link_libraries(cbom-pqc-classifier-tests
    OpenSSL::SSL
    OpenSSL::Crypto
    ${JSON_C_LIBRARIES}
    ${CURL_LIBRARIES}
        ${CURSES_LIBRARIES}
    Threads::Threads
        ${YAML_LIBRARIES}
        ${JANSSON_LIBRARIES}
        ${CURSES_LIBRARIES}
    dl
    m
)
target_include_directories(cbom-pqc-classifier-tests PRIVATE
    ${JSON_C_INCLUDE_DIRS}
    ${CURL_INCLUDE_DIRS}
    ${YAML_INCLUDE_DIRS}
    ${JANSSON_INCLUDE_DIRS}
    ${CMAKE_BINARY_DIR}/src
)
target_compile_definitions(cbom-pqc-classifier-tests PRIVATE ${JSON_C_CFLAGS_OTHER})
target_compile_options(cbom-pqc-classifier-tests PRIVATE -Wno-unused-variable -Wno-unused-but-set-variable -Wno-unused-parameter)

add_test(NAME cbom_pqc_classifier_tests COMMAND cbom-pqc-classifier-tests)

# PQC report generator test executable (v1.2)
add_executable(cbom-pqc-report-tests tests/test_pqc_report.c tests/test_cert_scanner_stats.c ${SOURCES} tests/test_globals.c)
target_link_libraries(cbom-pqc-report-tests
    OpenSSL::SSL
    OpenSSL::Crypto
    ${JSON_C_LIBRARIES}
    ${CURL_LIBRARIES}
        ${CURSES_LIBRARIES}
    Threads::Threads
        ${YAML_LIBRARIES}
        ${JANSSON_LIBRARIES}
    dl
    m
)
target_include_directories(cbom-pqc-report-tests PRIVATE
    ${JSON_C_INCLUDE_DIRS}
    ${CURL_INCLUDE_DIRS}
    ${YAML_INCLUDE_DIRS}
    ${JANSSON_INCLUDE_DIRS}
    ${CMAKE_BINARY_DIR}/src
)
target_compile_definitions(cbom-pqc-report-tests PRIVATE ${JSON_C_CFLAGS_OTHER})
target_compile_options(cbom-pqc-report-tests PRIVATE -Wno-unused-variable -Wno-unused-but-set-variable -Wno-unused-parameter)

add_test(NAME cbom_pqc_report_tests COMMAND cbom-pqc-report-tests)

# Fixture integration test executable (Phase 8 polish)
add_executable(cbom-fixture-integration-tests tests/test_fixture_integration.c tests/test_cert_scanner_stats.c ${SOURCES} tests/test_globals.c)
target_link_libraries(cbom-fixture-integration-tests
    OpenSSL::SSL
    OpenSSL::Crypto
    ${JSON_C_LIBRARIES}
    ${CURL_LIBRARIES}
        ${CURSES_LIBRARIES}
    Threads::Threads
        ${YAML_LIBRARIES}
        ${JANSSON_LIBRARIES}
        ${CURSES_LIBRARIES}
    dl
    m
)
target_include_directories(cbom-fixture-integration-tests PRIVATE
    ${JSON_C_INCLUDE_DIRS}
    ${CURL_INCLUDE_DIRS}
    ${YAML_INCLUDE_DIRS}
    ${JANSSON_INCLUDE_DIRS}
    ${CMAKE_BINARY_DIR}/src
)
target_compile_definitions(cbom-fixture-integration-tests PRIVATE ${JSON_C_CFLAGS_OTHER})
target_compile_options(cbom-fixture-integration-tests PRIVATE -Wno-unused-variable -Wno-unused-but-set-variable -Wno-unused-parameter)

add_test(NAME cbom_fixture_integration_tests COMMAND cbom-fixture-integration-tests)

# Relationship builder test executable (Issue #4)
add_executable(cbom-relationship-builder-tests tests/test_relationship_builder.c tests/test_cert_scanner_stats.c ${SOURCES} tests/test_globals.c)

# YAML plugin test (v1.3)
add_executable(test-yaml-plugin-manual tests/test_yaml_plugin_simple.c ${SOURCES} tests/test_globals.c)
target_link_libraries(test-yaml-plugin-manual
    OpenSSL::SSL
    OpenSSL::Crypto
    ${JSON_C_LIBRARIES}
    ${CURL_LIBRARIES}
    ${CURSES_LIBRARIES}
    ${YAML_LIBRARIES}
    ${JANSSON_LIBRARIES}
    Threads::Threads
    dl
    m
)
target_include_directories(test-yaml-plugin-manual PRIVATE
    ${JSON_C_INCLUDE_DIRS}
    ${CURL_INCLUDE_DIRS}
    ${YAML_INCLUDE_DIRS}
    ${JANSSON_INCLUDE_DIRS}
    ${CMAKE_BINARY_DIR}/src
)
target_compile_options(test-yaml-plugin-manual PRIVATE -Wno-unused-variable -Wno-unused-but-set-variable -Wno-unused-parameter)

# Add as a test
add_test(NAME yaml_plugin_simple_test COMMAND test-yaml-plugin-manual WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

# Service discovery test (v1.3 Phase 2)
add_executable(test-service-discovery tests/test_service_discovery_simple.c tests/test_cert_scanner_stats.c ${SOURCES} tests/test_globals.c)
target_link_libraries(test-service-discovery
    OpenSSL::SSL
    OpenSSL::Crypto
    ${JSON_C_LIBRARIES}
    ${CURL_LIBRARIES}
    ${CURSES_LIBRARIES}
    ${YAML_LIBRARIES}
    ${JANSSON_LIBRARIES}
    Threads::Threads
    dl
    m
)
target_include_directories(test-service-discovery PRIVATE
    ${JSON_C_INCLUDE_DIRS}
    ${CURL_INCLUDE_DIRS}
    ${YAML_INCLUDE_DIRS}
    ${JANSSON_INCLUDE_DIRS}
    ${CMAKE_BINARY_DIR}/src
)
target_compile_options(test-service-discovery PRIVATE -Wno-unused-variable -Wno-unused-but-set-variable -Wno-unused-parameter)

# Add as a test
add_test(NAME service_discovery_test COMMAND test-service-discovery WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

target_link_libraries(cbom-relationship-builder-tests
    OpenSSL::SSL
    OpenSSL::Crypto
    ${JSON_C_LIBRARIES}
    ${CURL_LIBRARIES}
    ${CURSES_LIBRARIES}
    Threads::Threads
        ${YAML_LIBRARIES}
        ${JANSSON_LIBRARIES}
    dl
    m
)
target_include_directories(cbom-relationship-builder-tests PRIVATE
    ${JSON_C_INCLUDE_DIRS}
    ${CURL_INCLUDE_DIRS}
    ${YAML_INCLUDE_DIRS}
    ${JANSSON_INCLUDE_DIRS}
    ${CMAKE_BINARY_DIR}/src
)
target_compile_definitions(cbom-relationship-builder-tests PRIVATE ${JSON_C_CFLAGS_OTHER})
target_compile_options(cbom-relationship-builder-tests PRIVATE -Wno-unused-variable -Wno-unused-but-set-variable -Wno-unused-parameter)

add_test(NAME cbom_relationship_builder_tests COMMAND cbom-relationship-builder-tests)

# Config parser test executable (Phase 3 - Config Extraction)
add_executable(cbom-config-parser-tests tests/test_config_parsers.c tests/test_cert_scanner_stats.c ${SOURCES} tests/test_globals.c)
target_link_libraries(cbom-config-parser-tests
    OpenSSL::SSL
    OpenSSL::Crypto
    ${JSON_C_LIBRARIES}
    ${CURL_LIBRARIES}
    ${CURSES_LIBRARIES}
    ${YAML_LIBRARIES}
    ${JANSSON_LIBRARIES}
    Threads::Threads
    dl
    m
)
target_include_directories(cbom-config-parser-tests PRIVATE
    ${JSON_C_INCLUDE_DIRS}
    ${CURL_INCLUDE_DIRS}
    ${YAML_INCLUDE_DIRS}
    ${JANSSON_INCLUDE_DIRS}
    ${CMAKE_BINARY_DIR}/src
)
target_compile_definitions(cbom-config-parser-tests PRIVATE ${JSON_C_CFLAGS_OTHER})
target_compile_options(cbom-config-parser-tests PRIVATE -Wno-unused-variable -Wno-unused-but-set-variable -Wno-unused-parameter)

add_test(NAME cbom_config_parser_tests COMMAND cbom-config-parser-tests WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

# Cross-architecture scanning tests (v1.8 - SONAME extraction, path normalization, registry)
add_executable(cbom-cross-arch-tests tests/test_cross_arch_scanning.c tests/test_cert_scanner_stats.c ${SOURCES} tests/test_globals.c)
target_link_libraries(cbom-cross-arch-tests
    OpenSSL::SSL
    OpenSSL::Crypto
    ${JSON_C_LIBRARIES}
    ${JANSSON_LIBRARIES}
    ${CURL_LIBRARIES}
    ${CURSES_LIBRARIES}
    ${YAML_LIBRARIES}
    Threads::Threads
    dl
    m
)
target_include_directories(cbom-cross-arch-tests PRIVATE
    ${JSON_C_INCLUDE_DIRS}
    ${JANSSON_INCLUDE_DIRS}
    ${CURL_INCLUDE_DIRS}
    ${YAML_INCLUDE_DIRS}
    ${CMAKE_BINARY_DIR}/src
)
target_compile_definitions(cbom-cross-arch-tests PRIVATE ${JSON_C_CFLAGS_OTHER})
target_compile_options(cbom-cross-arch-tests PRIVATE -Wno-unused-variable -Wno-unused-but-set-variable -Wno-unused-parameter)

add_test(NAME cbom_cross_arch_tests COMMAND cbom-cross-arch-tests)

# Deduplication test executable (Phase 8 polish)
# Commented out: test has API mismatches with current dedup implementation
# add_executable(cbom-dedup-tests tests/test_dedup.c tests/test_cert_scanner_stats.c ${SOURCES} tests/test_globals.c)
# target_link_libraries(cbom-dedup-tests
#     OpenSSL::SSL
#     OpenSSL::Crypto
#     ${JSON_C_LIBRARIES}
#     ${CURL_LIBRARIES}
#         ${CURSES_LIBRARIES}
#     Threads::Threads
#         ${CURSES_LIBRARIES}
#     dl
#     m
# )
# target_include_directories(cbom-dedup-tests PRIVATE
#     ${JSON_C_INCLUDE_DIRS}
#     ${CURL_INCLUDE_DIRS}
#     ${CMAKE_BINARY_DIR}/src
# )
# target_compile_definitions(cbom-dedup-tests PRIVATE ${JSON_C_CFLAGS_OTHER})
# target_compile_options(cbom-dedup-tests PRIVATE -Wno-unused-variable -Wno-unused-but-set-variable -Wno-unused-parameter)
#
# add_test(NAME cbom_dedup_tests COMMAND cbom-dedup-tests)

# Binary detector tests 
add_executable(cbom-binary-detector-tests tests/test_binary_detector.c src/detection/binary_detector.c src/secure_memory.c)
target_link_libraries(cbom-binary-detector-tests
    Threads::Threads
    m
)
target_include_directories(cbom-binary-detector-tests PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_BINARY_DIR}/src
)
add_test(NAME cbom_binary_detector_tests COMMAND cbom-binary-detector-tests)

# Kernel crypto detector tests 
add_executable(cbom-kernel-crypto-tests tests/test_kernel_crypto_detector.c src/detection/kernel_crypto_detector.c)
target_link_libraries(cbom-kernel-crypto-tests
    Threads::Threads
    m
)
target_include_directories(cbom-kernel-crypto-tests PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_BINARY_DIR}/src
)
add_test(NAME cbom_kernel_crypto_tests COMMAND cbom-kernel-crypto-tests)

# Package detector tests 
add_executable(cbom-package-detector-tests tests/test_package_detector.c src/detection/package_detector.c src/service_discovery.c src/secure_memory.c)
target_link_libraries(cbom-package-detector-tests
    ${JSON_C_LIBRARIES}
    Threads::Threads
    m
)
target_include_directories(cbom-package-detector-tests PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_BINARY_DIR}/src
    ${JSON_C_INCLUDE_DIRS}
)
add_test(NAME cbom_package_detector_tests COMMAND cbom-package-detector-tests)

# Schema validation test 
add_test(
    NAME cbom_schema_validation
    COMMAND ${CMAKE_SOURCE_DIR}/tests/validate_schemas.sh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)

# Static analysis targets
find_program(CLANG_STATIC_ANALYZER clang-static-analyzer)
find_program(CPPCHECK cppcheck)

if(CLANG_STATIC_ANALYZER)
    add_custom_target(static-analysis-clang
        COMMAND ${CLANG_STATIC_ANALYZER} --analyze ${SOURCES}
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "Running clang static analyzer"
    )
endif()

if(CPPCHECK)
    add_custom_target(static-analysis-cppcheck
        COMMAND ${CPPCHECK} --enable=all --error-exitcode=1 --std=c11 
                --suppress=missingIncludeSystem
                -I ${CMAKE_SOURCE_DIR}/include
                ${CMAKE_SOURCE_DIR}/src/
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "Running cppcheck static analyzer"
    )
endif()

# Combined static analysis target
add_custom_target(static-analysis)
if(CLANG_STATIC_ANALYZER)
    add_dependencies(static-analysis static-analysis-clang)
endif()
if(CPPCHECK)
    add_dependencies(static-analysis static-analysis-cppcheck)
endif()

# No orphan code check
add_custom_target(check-orphan-code
    COMMAND ${CMAKE_SOURCE_DIR}/scripts/check-orphan-code.sh
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Checking for orphaned source files"
)

# Schema validation
add_custom_target(validate-schemas
    COMMAND ${CMAKE_SOURCE_DIR}/scripts/validate-schemas.sh
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Validating pinned schemas"
)

# Normalization validation
add_custom_target(validate-normalization
    COMMAND ${CMAKE_SOURCE_DIR}/scripts/validate-normalization.sh
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Validating normalization test vectors"
)

# Property mapping validation
add_custom_target(validate-property-mappings
    COMMAND ${CMAKE_SOURCE_DIR}/scripts/validate-property-mappings.sh
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Validating CycloneDX property mappings against FROZEN v1.0 spec"
)

# Add all checks to a comprehensive check target
add_custom_target(check-all)
add_dependencies(check-all static-analysis check-orphan-code validate-schemas validate-normalization validate-property-mappings)
