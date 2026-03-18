#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "pcre2::pcre2-8-static" for configuration "Release"
set_property(TARGET pcre2::pcre2-8-static APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(pcre2::pcre2-8-static PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "C"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/libpcre2-8.a"
  )

list(APPEND _cmake_import_check_targets pcre2::pcre2-8-static )
list(APPEND _cmake_import_check_files_for_pcre2::pcre2-8-static "${_IMPORT_PREFIX}/lib/libpcre2-8.a" )

# Import target "pcre2::pcre2-posix-static" for configuration "Release"
set_property(TARGET pcre2::pcre2-posix-static APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(pcre2::pcre2-posix-static PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "C"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/libpcre2-posix.a"
  )

list(APPEND _cmake_import_check_targets pcre2::pcre2-posix-static )
list(APPEND _cmake_import_check_files_for_pcre2::pcre2-posix-static "${_IMPORT_PREFIX}/lib/libpcre2-posix.a" )

# Import target "pcre2::pcre2-16-static" for configuration "Release"
set_property(TARGET pcre2::pcre2-16-static APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(pcre2::pcre2-16-static PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "C"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/libpcre2-16.a"
  )

list(APPEND _cmake_import_check_targets pcre2::pcre2-16-static )
list(APPEND _cmake_import_check_files_for_pcre2::pcre2-16-static "${_IMPORT_PREFIX}/lib/libpcre2-16.a" )

# Import target "pcre2::pcre2-32-static" for configuration "Release"
set_property(TARGET pcre2::pcre2-32-static APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(pcre2::pcre2-32-static PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "C"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/libpcre2-32.a"
  )

list(APPEND _cmake_import_check_targets pcre2::pcre2-32-static )
list(APPEND _cmake_import_check_files_for_pcre2::pcre2-32-static "${_IMPORT_PREFIX}/lib/libpcre2-32.a" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
