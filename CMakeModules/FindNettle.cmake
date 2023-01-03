# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

#[=======================================================================[.rst:
FindNettle
----------

Find the Nettle library

IMPORTED Targets
^^^^^^^^^^^^^^^^

.. versionadded:: 3.16

This module defines :prop_tgt:`IMPORTED` target ``Nettle``, if
nettle has been found.

Result Variables
^^^^^^^^^^^^^^^^

``NETTLE_FOUND``
  System has nettle
``NETTLE_INCLUDE_DIR``
  The nettle include directory
``NETTLE_LIBRARIES``
  The libraries needed to use nettle
``NETTLE_DEFINITIONS``
  Compiler switches required for using nettle
``NETTLE_VERSION``
  version of nettle.
#]=======================================================================]


if (NETTLE_INCLUDE_DIR AND NETTLE_LIBRARY)
  # in cache already
  set(nettle_FIND_QUIETLY TRUE)
endif ()

if (NOT WIN32)
  # try using pkg-config to get the directories and then use these values
  # in the find_path() and find_library() calls
  # also fills in NETTLE_DEFINITIONS, although that isn't normally useful
  find_package(PkgConfig QUIET)
  PKG_CHECK_MODULES(PC_NETTLE QUIET nettle)
  set(NETTLE_DEFINITIONS ${PC_NETTLE_CFLAGS_OTHER})
  set(NETTLE_VERSION ${PC_NETTLE_VERSION})
  # keep for backward compatibility
  set(NETTLE_VERSION_STRING ${PC_NETTLE_VERSION})
endif ()

find_path(NETTLE_INCLUDE_DIR nettle/nettle-types.h
  HINTS
    ${PC_NETTLE_INCLUDEDIR}
    ${PC_NETTLE_INCLUDE_DIRS}
  )

find_library(NETTLE_LIBRARY NAMES nettle libnettle
  HINTS
    ${PC_NETTLE_LIBDIR}
    ${PC_NETTLE_LIBRARY_DIRS}
  )

mark_as_advanced(NETTLE_INCLUDE_DIR NETTLE_LIBRARY)

include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(Nettle
                                  REQUIRED_VARS NETTLE_LIBRARY NETTLE_INCLUDE_DIR
                                  VERSION_VAR NETTLE_VERSION_STRING)

if(NETTLE_FOUND)
  set(NETTLE_LIBRARIES    ${NETTLE_LIBRARY})
  set(NETTLE_INCLUDE_DIRS ${NETTLE_INCLUDE_DIR})

  if(NOT TARGET Nettle)
    add_library(Nettle UNKNOWN IMPORTED)
    set_target_properties(Nettle PROPERTIES
      INTERFACE_INCLUDE_DIRECTORIES "${NETTLE_INCLUDE_DIRS}"
      INTERFACE_COMPILE_DEFINITIONS "${NETTLE_DEFINITIONS}"
      IMPORTED_LINK_INTERFACE_LANGUAGES "C"
      IMPORTED_LOCATION "${NETTLE_LIBRARIES}")
  endif()
endif()
