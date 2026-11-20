# AGENTS.md

This file provides guidance to AI coding agents when working with code in this repository.

## Overview

libpwsafe is a C17 library for reading and writing Password Safe v1 and v2 database files. The format uses Blowfish-CBC encryption with a SHA-1-derived key. Much of the code is adapted from Nicolas Dade's pwsafe (github.com/nsd20463/pwsafe). It is GPL-3.0 licensed. Dependencies are OpenSSL (libcrypto) and GoogleTest (tests only). Doxygen is needed when `LIBPWSAFE_BUILD_DOCS=ON`, which is the default on Linux.

## Build / test

Builds use CMake presets with the Unix Makefiles generator on Linux. Every preset writes to `./build`, so switching presets reuses that same directory.

```sh
cmake --preset=x64-linux-gcc-debug        # or x64-linux-clang-*, *-release; x64-windows-msvc-* (needs VCPKG_ROOT)
cmake --build --preset=x64-linux-gcc-debug
ctest --preset=x64-linux-gcc-debug
```

- **Run a single test:** `ctest --preset=x64-linux-gcc-debug -R ReadDbV2Succeeds`. You can also run the binary from `test/`, because tests open fixtures by the relative path `data/*.dat`: `cd test && ../build/test/libpwsafe-test --gtest_filter=Test.ReadDbV2Succeeds`. CTest already sets the working directory to `test/`.
- **Useful configure options:**
  - `-DLIBPWSAFE_BUILD_DOCS=OFF` skips Doxygen.
  - `-DLIBPWSAFE_DEBUG_SANITIZE=ON` turns on ASan/UBSan in Debug builds and needs a full rebuild.
  - Also available: `LIBPWSAFE_BUILD_TESTS`, `LIBPWSAFE_BUILD_SHARED`, `LIBPWSAFE_BUILD_STATIC`.
- **Lint:** if `/usr/bin/clang-tidy` exists, it runs automatically on the library sources during the build. The check list is in `src/CMakeLists.txt`.
- **Format:** `.clang-format` uses the Microsoft style.
- **Packaging:** run `cd build && cpack -G TGZ` (CI uses ZIP on Windows).
- **CI:** `.github/workflows/build-project.yml` builds the gcc-release preset on Ubuntu and the msvc-release preset on Windows. It runs on pushes to `main` and `dev/*`, and on `v*` tags, which also publish a release.

## Architecture

- `api/pwsafe.h` is the only public header and a pure C API. Its main types are:
  - `PwsDbRecord` and `PwsDbField`, which are caller-visible singly linked lists. The caller frees them with `pws_free_db_records()`.
  - Field type codes (`PwsFieldType`).
  - `PwsResultCode`.

  Public functions return a bool-like `int` and report errors through an optional `int *rc` out-parameter.
- `src/pwsafe_priv.h` holds internal types: `PwsDb`, which carries the file handle, the header, the Blowfish key schedule and the CBC state, plus `Header` and `Block` (8 bytes). It also declares the internal functions that tests call directly.
- `src/db.c` is nearly all of the logic:
  - **Key and password check:** `db_compute_key` derives the key as SHA-1(password + salt), then Blowfish. `generate_hash` and `db_check_password` verify the password against the header's random value and hash.
  - **Block cipher:** `db_encode_block` and `db_decode_block` byte-swap each 8-byte block around Blowfish ECB and handle the CBC chaining themselves. Original Password Safe treated blocks as little-endian 32-bit ints, which is why the swap is there.
  - **Reading:** reads auto-detect the format version. A v2 file starts with a v1-style "ident" record whose name is `PWSAFE_V2_NAME_MAGIC`. v1 records pack name/user into a single field split by `SPLIT_CHAR` (`0xAD`) and are converted into typed fields.
  - **Writing:** `pws_db_write` always writes v2. It writes to a temp file `<path>.<random>.tmp` opened with `O_EXCL`, then renames it over the target (`MoveFileExA` on Windows), so a failed write leaves the existing file untouched. Records with no `FT_UUID` field get one generated.
  - **Read limits:** `MAX_FIELD_LEN` (64 KiB) and `MAX_RECORD_COUNT` guard against corrupt or truncated input. Tests cover every truncation length of the fixture files.
- `src/block.c` handles byte order and block helpers. The system byte order is detected at runtime with `eval_sys_byte_order()`.
- `src/util.c` holds the UUID hex/binary conversion, `trim_right`, and `get_default_user` (which uses `getpwuid` when `HAVE_PWUID` is set).
- **Build targets:**
  - The sources compile once into the OBJECT library `objlib`, which feeds both `pwsafe` (shared) and `pwsafeStatic`.
  - The test binary links the static library, so tests can reach internal (non-API) symbols.
  - On Windows the shared library exports symbols via `WINDOWS_EXPORT_ALL_SYMBOLS`, and the static library is named `libpwsafe.lib` so it doesn't clash with the DLL's import lib.
- `config.h` is generated into the build directory from `config.h.in` and provides `LIBPWSAFE_VERSION` and `HAVE_PWUID`.
- Compiler warnings and debug flags live in `cmake/toolchain-*.cmake`, not in `CMakeLists.txt`.

## Conventions

- Clear secrets with `memset_func` (a volatile function pointer to `memset`) so the compiler can't optimize the wipe away. Zero key material and temporary blocks after use.
- Keep platform code behind `#ifdef _WIN32`. The tests include POSIX shims (`setenv`/`unsetenv`) for MSVC.
- Test fixtures are `test/data/test-v{1,2}[-empty].dat`, and the password for all of them is `password`.
