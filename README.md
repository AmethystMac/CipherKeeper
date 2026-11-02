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

**Where the vault lives.** `--vault PATH` if given, else `$CK_VAULT`, else `vault.ckvault` in your user data
folder: `%LOCALAPPDATA%\CipherKeeper` on Windows, `~/Library/Application Support/CipherKeeper` on macOS and
`$XDG_DATA_HOME/cipherkeeper` (default `~/.local/share/cipherkeeper`) on Linux.

**Exit codes:** `0` success, `1` the command failed (no such item, cancelled input, vault error), `2` bad command
line, `3` wrong master password three times.

## Layout

```
core/      libcipherkeeper: crypto, vault, item model, sync client (no Qt, no UI)
cli/       command-line front end (ck)
gui/       Qt 6 desktop app
server/    sync server (Phase 3)
tests/     Catch2 tests
```
