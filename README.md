# CipherKeeper

**Every secret sealed. Only you hold the key.**

Keep a password on this device alone, or sync it end-to-end encrypted across all of yours. Either way, nobody
else can read it, not even the server.

> Early development (Phase 1 in progress). The `ck` command-line tool works on a local vault, and the desktop app
> is still a placeholder. Don't store real passwords in it.

The 2023 Crypto++ prototype is kept in git history under the `legacy-prototype` tag.

## How your passwords are protected

**Your master password doesn't lock your passwords. It opens a safe, and inside the safe are the keys that do.**

- **The master password is the combination to a safe.** It exists only in your head. CipherKeeper never writes it
  down, on your device or anywhere else.
- **The safe holds keys, not passwords.** Those keys lock your items.

### On your laptop

- When you create a vault, CipherKeeper makes a brand-new random key (the **Local Vault Key**). Every item you save
  is locked with it. The key goes into the safe, and the safe is stored in the vault file.
- When you unlock, you enter the combination, the safe opens, and CipherKeeper uses the key inside to open items as
  you view them.
- If you enter the wrong combination, the safe stays shut. That's how CipherKeeper knows the password is wrong,
  without ever keeping a copy of it.
- **Changing your master password only changes the safe's combination.** The key inside stays the same, so none of
  your items have to be locked again. That's why it's instant.

### On your phone too

The phone gets its own vault, its own safe and its own brand-new key. You use the same combination on both, but the
keys inside are different. The laptop's key never leaves the laptop, so local items stay on the device that saved
them.

## Building

Dependencies (libsodium, SQLite, Catch2, Qt) come from **vcpkg** and are downloaded and compiled on the first
configure. You only install the toolchain and vcpkg itself.

### Windows

1. Install Visual Studio 2022 with the "Desktop development with C++" workload. It includes CMake and Ninja.
2. Get vcpkg:

```bash
git clone https://github.com/microsoft/vcpkg.git C:/dev/vcpkg
```

```bash
C:/dev/vcpkg/bootstrap-vcpkg.bat -disableMetrics
```

3. Set the `VCPKG_ROOT` environment variable to `C:\dev\vcpkg`.
4. Run the build commands below from a Visual Studio **x64** Native Tools prompt.

### Linux (Debian, Ubuntu, Raspberry Pi OS)

1. Install a compiler, CMake, Ninja, git, the tools vcpkg needs to download and unpack packages, and the autotools
   it uses to build libsodium:

```bash
sudo apt update
```

```bash
sudo apt install build-essential cmake ninja-build git curl zip unzip tar pkg-config autoconf autoconf-archive automake libtool
```

   You need GCC 11 or newer and CMake 3.25 or newer. Check with `g++ --version` and `cmake --version`. Debian 12+,
   Ubuntu 24.04+ and current Raspberry Pi OS have both. On Ubuntu 22.04 the packaged CMake (3.22) is too old: get a
   newer one from [Kitware's APT repository](https://apt.kitware.com/) or `sudo snap install cmake --classic`.

2. Optional, to check your code the way CI does (formatting and clang-tidy):

```bash
sudo apt install clang-format clang-tidy
```

3. Optional, only for the `gui-debug` preset (Qt needs the X11 and OpenGL headers):

```bash
sudo apt install '^libxcb.*-dev' libx11-xcb-dev libglu1-mesa-dev libxrender-dev libxi-dev libxkbcommon-dev libxkbcommon-x11-dev libegl1-mesa-dev python3
```

4. Get vcpkg:

```bash
git clone https://github.com/microsoft/vcpkg.git ~/vcpkg
```

```bash
~/vcpkg/bootstrap-vcpkg.sh -disableMetrics
```

5. Point `VCPKG_ROOT` at it, in your shell profile so it survives new terminals:

```bash
echo 'export VCPKG_ROOT="$HOME/vcpkg"' >> ~/.bashrc
```

   **On ARM (Raspberry Pi, other aarch64 boards)**, vcpkg has no prebuilt CMake or Ninja to download and stops
   unless you tell it to use the ones you installed with apt:

```bash
echo 'export VCPKG_FORCE_SYSTEM_BINARIES=1' >> ~/.bashrc
```

   Then open a new terminal (or run `source ~/.bashrc`) and check that `echo $VCPKG_ROOT` prints the path.

6. Run the build commands below from the repository folder.

### Build, test and run

Run these in order. Each one needs the one before it to have run at least once.

**1. Configure.** Sets up `build/debug/` and installs the dependencies through vcpkg. You only need it the first
time, or after changing `CMakeLists.txt`, `CMakePresets.json` or `vcpkg.json`. The first run builds every dependency
from source, which takes several minutes (much longer on a Raspberry Pi). Later runs reuse them.

```bash
cmake --preset debug
```

**2. Build.** Compiles the core library, the `ck` CLI and the tests. Run it again after every code change. It only
recompiles what changed.

```bash
cmake --build --preset debug
```

**3. Test (optional).** Runs the test suite and shows the output of any test that fails. Skip it if you only want
to use the CLI.

```bash
ctest --preset debug
```

**4. Run.** The CLI ends up at `build/debug/cli/ck`. For example, this creates a vault (see
[Using the CLI](#using-the-cli)):

```bash
./build/debug/cli/ck init
```

To use another preset from the table below, put its name in place of `debug` in all three commands. Visual Studio can
also open the folder directly and pick up the presets.

| Preset | What it builds |
|---|---|
| `debug` / `release` | Core library, `ck` CLI and tests |
| `asan` | Debug with AddressSanitizer (plus UBSan on GCC/Clang) |
| `gui-debug` | Also the Qt 6 desktop app. The first configure compiles Qt through vcpkg, which takes a long time. |

Add `-DCK_CLANG_TIDY=ON` to the configure step to run clang-tidy. Formatting follows `.clang-format`.

## Using the CLI

```
ck [--vault PATH] <command> [arguments]
```

| Command | What it does |
|---|---|
| `init` | Create a new vault (missing parent folders are created) |
| `unlock` | Enter the master password once, then type commands at a `ck>` prompt until `lock`, `exit` or `quit` |
| `add <type>` | Add an item. Types: `login`, `note`, `card`, `identity` |
| `list [--type TYPE] [query]` | Show the short ID, type and title of matching items, sorted by title |
| `get [--show] [--field NAME] <query>` | Show an item. Secret fields are masked unless you pass `--show` |
| `edit <query>` | Change an item field by field. An empty answer keeps a field, `-` clears it |
| `rm [--yes] <query>` | Delete an item, asking first unless you pass `--yes` |
| `change-master` | Change the master password (asks for the current one, even inside `unlock`) |
| `gen [options]` | Print a new random password or passphrase. Needs no vault and no master password |
| `help`, `version` | Show usage or the version |

A first run looks like this:

```bash
ck init
```

```bash
ck add login
```

```bash
ck list
```

```bash
ck get --show bank
```

- **Passwords are always typed, never passed as arguments**, since arguments end up in shell history. The master
  password, item passwords, TOTP secrets, card numbers, security codes and hidden custom fields are read without
  echo. Every other field is asked for one prompt at a time.
- **The master password is asked for when a command needs it**, with three tries. Use `ck unlock` to enter it once
  and run several commands. `init` and `unlock` aren't available inside an unlock session.
- **A query picks one item**, ignoring case. An ID prefix of at least 4 characters wins first, then an exact title,
  then a title that contains the query. It must match exactly one item. Quote titles with spaces at the `ck>`
  prompt (`get "My Bank"`).
- **`get --field NAME`** prints only that field's value (URLs and tags one per line). NAME is a custom field's name
  or one of `title`, `notes`, `category`, `tags`, `username`, `password`, `urls`, `totp_secret`, `cardholder_name`,
  `brand`, `number`, `expiry`, `security_code`, `first_name`, `middle_name`, `last_name`, `company`, `email`,
  `phone`, `address_line1`, `address_line2`, `city`, `region`, `postal_code`, `country`.
- **`ck gen`** prints one password and nothing else, so you can copy it or pipe it. With no options it's 20
  characters with lowercase and uppercase letters, digits and symbols, at least one of each.
  - `--length N` sets the length (1 to 1024).
  - `--no-lower`, `--no-upper`, `--no-digits` and `--no-symbols` leave out a kind of character.
  - `--no-ambiguous` leaves out look-alikes (`I l 1 O 0 |`).
  - `--words N` prints a passphrase of N words (4 to 20) from the EFF wordlist, separated by spaces. It can't be
    combined with the other options.

  A bad option or an impossible setting (for example every kind turned off) exits with `2`.

  ```bash
  ck gen --length 32 --no-symbols
  ```

  ```bash
  ck gen --words 6
  ```

**Where the vault lives.** `--vault PATH` if given, else `$CK_VAULT`, else `vault.ckvault` in your user data
folder: `%LOCALAPPDATA%\CipherKeeper` on Windows, `~/Library/Application Support/CipherKeeper` on macOS and
`$XDG_DATA_HOME/cipherkeeper` (default `~/.local/share/cipherkeeper`) on Linux.

**Exit codes:** `0` success, `1` the command failed (no such item, cancelled input, vault error), `2` bad command
line, `3` wrong master password three times.

## Layout

```
core/      libcipherkeeper: crypto, vault, item model, password generator, sync client (no Qt, no UI)
  data/    the EFF large wordlist used for passphrases
cli/       command-line front end (ck)
gui/       Qt 6 desktop app
server/    sync server (Phase 3)
tests/     Catch2 tests
```

## Credits

Passphrases use the [EFF large wordlist](https://www.eff.org/dice) by the Electronic Frontier Foundation, licensed
under [CC BY 3.0 US](https://creativecommons.org/licenses/by/3.0/us/). `core/data/eff_large_wordlist.txt` is EFF's
file, unchanged; `core/src/generator/eff_large_wordlist.cpp` holds the same words as a C++ table.
