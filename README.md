# CipherKeeper

A zero-knowledge password manager written in C++20. Each entry is stored either local-only or end-to-end
encrypted in the cloud and synced across your devices.

> Early development (Phase 0 done). There is no working vault yet. Don't store real passwords in it.

The 2023 Crypto++ prototype is kept in git history under the `legacy-prototype` tag.

## Building

You need:
- **Windows:** Visual Studio 2022 with the "Desktop development with C++" workload (includes CMake and Ninja).
- **Linux:** a C++20 compiler, CMake ≥ 3.25, Ninja, and the autotools vcpkg needs to build libsodium
  (`sudo apt install ninja-build autoconf autoconf-archive automake libtool` on Debian/Ubuntu).
- **vcpkg** (all platforms), with `VCPKG_ROOT` pointing at it:

```bash
git clone https://github.com/microsoft/vcpkg.git C:/dev/vcpkg
```

```bash
C:/dev/vcpkg/bootstrap-vcpkg.bat -disableMetrics
```

Then set the `VCPKG_ROOT` environment variable to `C:\dev\vcpkg`. On Linux, use `./bootstrap-vcpkg.sh` and
`export VCPKG_ROOT=...`.

Build and test from a Visual Studio "x64 Native Tools" prompt (Windows) or any shell (Linux):

```bash
cmake --preset debug
```

```bash
cmake --build --preset debug
```

```bash
ctest --preset debug
```

The CLI ends up at `build/debug/cli/ck`. Visual Studio can also open the folder directly and pick up the presets.

| Preset | What it builds |
|---|---|
| `debug` / `release` | Core library, `ck` CLI and tests |
| `asan` | Debug with AddressSanitizer (plus UBSan on GCC/Clang) |
| `gui-debug` | Also the Qt 6 desktop app. The first configure compiles Qt through vcpkg, which takes a long time. |

Add `-DCK_CLANG_TIDY=ON` to the configure step to run clang-tidy. Formatting follows `.clang-format`.

## Layout

```
core/      libcipherkeeper: crypto, vault, item model, sync client (no Qt, no UI)
cli/       command-line front end (ck)
gui/       Qt 6 desktop app
server/    sync server (Phase 3)
tests/     Catch2 tests
```
