# Additional clean files
cmake_minimum_required(VERSION 3.16)

if("${CONFIG}" STREQUAL "" OR "${CONFIG}" STREQUAL "")
  file(REMOVE_RECURSE
  "CMakeFiles/tst_contacts_autogen.dir/AutogenUsed.txt"
  "CMakeFiles/tst_contacts_autogen.dir/ParseCache.txt"
  "CMakeFiles/tst_keys_autogen.dir/AutogenUsed.txt"
  "CMakeFiles/tst_keys_autogen.dir/ParseCache.txt"
  "tst_contacts_autogen"
  "tst_keys_autogen"
  )
endif()
