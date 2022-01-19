
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_program(CCACHE_PROGRAM ccache)
if(CCACHE_PROGRAM)
  foreach(lang C CXX)
    if(NOT DEFINED CMAKE_${lang}_COMPILER_LAUNCHER AND NOT CMAKE_${lang}_COMPILER MATCHES ".*/ccache")
      message(STATUS "Enabling ccache for ${lang}")
      set(CMAKE_${lang}_COMPILER_LAUNCHER ${CCACHE_PROGRAM} CACHE STRING "")
    endif()
  endforeach()
endif()

cmake_minimum_required(VERSION 3.7)

# Has to be set before `project()`, and ignored on non-macos:
set(CMAKE_OSX_DEPLOYMENT_TARGET 10.12 CACHE STRING "macOS deployment target (Apple clang only)")

project(libbmq
    VERSION 1.2.10
    LANGUAGES CXX C)

include(GNUInstallDirs)

message(STATUS "bmq v${PROJECT_VERSION}")

set(BMQ_LIBVERSION 0)


if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    set(bmq_IS_TOPLEVEL_PROJECT TRUE)
else()
    set(bmq_IS_TOPLEVEL_PROJECT FALSE)
endif()


option(BUILD_SHARED_LIBS "Build shared libraries instead of static ones" ON)
set(bmq_INSTALL_DEFAULT OFF)
if(BUILD_SHARED_LIBS OR bmq_IS_TOPLEVEL_PROJECT)
    set(bmq_INSTALL_DEFAULT ON)
endif()
option(BMQ_BUILD_TESTS "Building and perform bmq tests" ${bmq_IS_TOPLEVEL_PROJECT})
option(BMQ_INSTALL "Add bmq libraries and headers to cmake install target; defaults to ON if BUILD_SHARED_LIBS is enabled or we are the top-level project; OFF for a static subdirectory build" ${bmq_INSTALL_DEFAULT})
option(BMQ_INSTALL_CPPZMQ "Install cppzmq header with bmq/ headers (requires BMQ_INSTALL)" ON)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

configure_file(bmq/version.h.in bmq/version.h @ONLY)
configure_file(libbmq.pc.in libbmq.pc @ONLY)


add_library(bmq
    bmq/address.cpp
    bmq/auth.cpp
    bmq/bt_serialize.cpp
    bmq/connections.cpp
    bmq/jobs.cpp
    bmq/bmq.cpp
    bmq/proxy.cpp
    bmq/worker.cpp
)
set_target_properties(bmq PROPERTIES SOVERSION ${BMQ_LIBVERSION})

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
target_link_libraries(bmq PRIVATE Threads::Threads)

# libzmq is nearly impossible to link statically from a system-installed static library: it depends
# on a ton of other libraries, some of which are not all statically available.  If the caller wants
# to mess with this, so be it: they can set up a libzmq target and we'll use it.  Otherwise if they
# asked us to do things statically, don't even try to find a system lib and just build it.
set(bmq_build_static_libzmq OFF)
if(TARGET libzmq)
    target_link_libraries(bmq PUBLIC libzmq)
elseif(BUILD_SHARED_LIBS)
    include(FindPkgConfig)
    pkg_check_modules(libzmq libzmq>=4.3 IMPORTED_TARGET)

    if(libzmq_FOUND)
        # Debian sid includes a -isystem in the mit-krb package that, starting with pkg-config 0.29.2,
        # breaks cmake's pkgconfig module because it stupidly thinks "-isystem" is a path, so if we find
        # -isystem in the include dirs then hack it out.
        get_property(zmq_inc TARGET PkgConfig::libzmq PROPERTY INTERFACE_INCLUDE_DIRECTORIES)
        list(FIND zmq_inc "-isystem" broken_isystem)
        if(NOT broken_isystem EQUAL -1)
          list(REMOVE_AT zmq_inc ${broken_isystem})
          set_property(TARGET PkgConfig::libzmq PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${zmq_inc})
        endif()

        target_link_libraries(bmq PUBLIC PkgConfig::libzmq)
    else()
        set(bmq_build_static_libzmq ON)
    endif()
else()
    set(bmq_build_static_libzmq ON)
endif()

if(bmq_build_static_libzmq)
    message(STATUS "libzmq >= 4.3 not found or static build requested, building bundled version")
    list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/local-libzmq")
    include(LocalLibzmq)
    target_link_libraries(bmq PUBLIC libzmq_vendor)
endif()

target_include_directories(bmq
    PUBLIC
        $<INSTALL_INTERFACE:>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/cppzmq>
)

target_compile_options(bmq PRIVATE -Wall -Wextra)

option(WARNINGS_AS_ERRORS "treat all warnings as errors" ON)
if(WARNINGS_AS_ERRORS)
    target_compile_options(bmq PRIVATE -Werror)
endif()

target_compile_features(bmq PUBLIC cxx_std_17)
set_target_properties(bmq PROPERTIES POSITION_INDEPENDENT_CODE ON)

function(link_dep_libs target linktype libdirs)
    foreach(lib ${ARGN})
        find_library(link_lib-${lib} NAMES ${lib} PATHS ${libdirs})
        if(link_lib-${lib})
            target_link_libraries(${target} ${linktype} ${link_lib-${lib}})
        endif()
    endforeach()
endfunction()

# If the caller has already set up a sodium target then we will just link to it, otherwise we go
# looking for it.
if(TARGET sodium)
    target_link_libraries(bmq PUBLIC sodium)
    if(bmq_build_static_libzmq)
        target_link_libraries(libzmq_vendor INTERFACE sodium)
    endif()
else()
    include(FindPkgConfig)
    pkg_check_modules(sodium REQUIRED libsodium IMPORTED_TARGET)

    if(BUILD_SHARED_LIBS)
        target_link_libraries(bmq PUBLIC PkgConfig::sodium)
        if(bmq_build_static_libzmq)
            target_link_libraries(libzmq_vendor INTERFACE PkgConfig::sodium)
        endif()
    else()
        link_dep_libs(bmq PUBLIC "${sodium_STATIC_LIBRARY_DIRS}" ${sodium_STATIC_LIBRARIES})
        target_include_directories(bmq PUBLIC ${sodium_STATIC_INCLUDE_DIRS})
        if(bmq_build_static_libzmq)
            link_dep_libs(libzmq_vendor INTERFACE "${sodium_STATIC_LIBRARY_DIRS}" ${sodium_STATIC_LIBRARIES})
            target_link_libraries(libzmq_vendor INTERFACE ${sodium_STATIC_INCLUDE_DIRS})
        endif()
    endif()
endif()

add_library(bmq::bmq ALIAS bmq)

export(
    TARGETS bmq
    NAMESPACE bmq::
    FILE bmqTargets.cmake
)

if(BMQ_INSTALL)
    install(
        TARGETS bmq
        EXPORT bmqConfig
        DESTINATION ${CMAKE_INSTALL_LIBDIR}
        )

    install(
        FILES bmq/address.h
        bmq/auth.h
        bmq/base32z.h
        bmq/base64.h
        bmq/batch.h
        bmq/bt_serialize.h
        bmq/bt_value.h
        bmq/byte_type.h
        bmq/connections.h
        bmq/hex.h
        bmq/bmq.h
        bmq/message.h
        bmq/variant.h
        ${CMAKE_CURRENT_BINARY_DIR}/bmq/version.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/bmq
        )

    if(BMQ_INSTALL_CPPZMQ)
        install(
            FILES cppzmq/zmq.hpp
            DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/bmq
            )
    endif()


    install(
        FILES ${CMAKE_CURRENT_BINARY_DIR}/libbmq.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
    )


endif()

if(BMQ_BUILD_TESTS)
    add_subdirectory(tests)
endif()
