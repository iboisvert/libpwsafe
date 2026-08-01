set(CMAKE_C_COMPILER clang)
set(CMAKE_CXX_COMPILER clang++)

set(CMAKE_C_FLAGS_INIT "-Wall -Wextra")
set(CMAKE_CXX_FLAGS_INIT "-Wall -Wextra")
set(CMAKE_C_FLAGS_DEBUG_INIT "-g -O0 -fno-omit-frame-pointer")
set(CMAKE_CXX_FLAGS_DEBUG_INIT "-g -O0 -fno-omit-frame-pointer")
set(LIBPWSAFE_SANITIZE_FLAGS "-fsanitize=address,undefined")

# Installed shared libs look for their dependencies alongside the executable
set(CMAKE_INSTALL_RPATH "$ORIGIN;$ORIGIN/..")
