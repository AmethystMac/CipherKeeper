#include "terminal.hpp"

#include <cipherkeeper/crypto/secure_buffer.hpp>

#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <shellapi.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

namespace ck::cli {

namespace {

constexpr std::size_t max_answer = 4096; // characters per answer

void write(std::FILE* stream, std::string_view text) {
    (void)std::fwrite(text.data(), 1, text.size(), stream);
    (void)std::fflush(stream);
}

std::string_view as_text(const SecureBuffer& buffer, std::size_t length) {
    return {reinterpret_cast<const char*>(buffer.data()), length};
}

std::runtime_error too_long() {
    return std::runtime_error("that answer is longer than " + std::to_string(max_answer) + " characters");
}

// Reads one line from a redirected stdin (or any POSIX stdin). std::nullopt at end of input.
std::optional<SecureString> read_stream_line() {
    SecureBuffer buffer(max_answer);
    const std::span<std::byte> bytes = buffer.bytes();
    std::size_t length = 0;
    bool overflow = false;
    bool got_any = false;
    while (true) {
        const int c = std::fgetc(stdin);
        if (c == EOF) {
            if (!got_any) {
                return std::nullopt;
            }
            break;
        }
        got_any = true;
        if (c == '\n') {
            break;
        }
        if (length == max_answer) {
            overflow = true; // keep reading so the rest of the line isn't taken as the next answer
            continue;
        }
        bytes[length++] = static_cast<std::byte>(c);
    }
    if (overflow) {
        throw too_long();
    }
    if (length > 0 && bytes[length - 1] == std::byte{'\r'}) {
        --length;
    }
    return SecureString(as_text(buffer, length));
}

#ifdef _WIN32

std::string to_utf8(std::wstring_view wide) {
    if (wide.empty()) {
        return {};
    }
    const int size =
        WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()), nullptr, 0, nullptr, nullptr);
    if (size <= 0) {
        throw std::runtime_error("can't convert text to UTF-8");
    }
    std::string text(static_cast<std::size_t>(size), '\0');
    (void)WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()), text.data(), size, nullptr,
                              nullptr);
    return text;
}

bool is_console(HANDLE input) {
    DWORD mode = 0;
    return GetConsoleMode(input, &mode) != 0;
}

class EchoOff {
  public:
    explicit EchoOff(HANDLE input) : input_(input) {
        if (GetConsoleMode(input_, &mode_) != 0) {
            active_ = SetConsoleMode(input_, mode_ & ~static_cast<DWORD>(ENABLE_ECHO_INPUT)) != 0;
        }
    }
    EchoOff(const EchoOff&) = delete;
    EchoOff& operator=(const EchoOff&) = delete;
    EchoOff(EchoOff&&) = delete;
    EchoOff& operator=(EchoOff&&) = delete;
    ~EchoOff() {
        if (active_) {
            (void)SetConsoleMode(input_, mode_);
        }
    }

    [[nodiscard]] bool active() const noexcept { return active_; }

  private:
    HANDLE input_;
    DWORD mode_ = 0;
    bool active_ = false;
};

// Reads one line from a Windows console as UTF-16, which (unlike narrow reads) handles non-ASCII input, and
// converts it to UTF-8. Both copies stay in secure memory.
std::optional<SecureString> read_console_line(HANDLE input) {
    SecureBuffer wide(max_answer * sizeof(wchar_t));
    const std::span<wchar_t> chars(reinterpret_cast<wchar_t*>(wide.data()), max_answer);
    std::size_t length = 0;
    bool overflow = false;
    while (true) {
        wchar_t& slot = chars[length == max_answer ? max_answer - 1 : length];
        DWORD read = 0;
        if (ReadConsoleW(input, &slot, 1, &read, nullptr) == 0) {
            throw std::runtime_error("can't read from the console");
        }
        if (read == 0) {
            return std::nullopt;
        }
        if (slot == L'\n') {
            break;
        }
        if (length == max_answer) {
            overflow = true;
        } else {
            ++length;
        }
    }
    if (overflow) {
        throw too_long();
    }
    if (length > 0 && chars[length - 1] == L'\r') {
        --length;
    }
    if (length > 0 && chars[0] == L'\x1a') { // Ctrl+Z, then Enter: end of input
        return std::nullopt;
    }
    if (length == 0) {
        return SecureString{};
    }

    const int size =
        WideCharToMultiByte(CP_UTF8, 0, chars.data(), static_cast<int>(length), nullptr, 0, nullptr, nullptr);
    if (size <= 0) {
        throw std::runtime_error("can't convert the answer to UTF-8");
    }
    SecureBuffer utf8(static_cast<std::size_t>(size));
    (void)WideCharToMultiByte(CP_UTF8, 0, chars.data(), static_cast<int>(length), reinterpret_cast<char*>(utf8.data()),
                              size, nullptr, nullptr);
    return SecureString(as_text(utf8, utf8.size()));
}

std::optional<std::filesystem::path> env_path(const wchar_t* name) {
    const DWORD size = GetEnvironmentVariableW(name, nullptr, 0);
    if (size <= 1) {
        return std::nullopt;
    }
    std::wstring value(size, L'\0');
    const DWORD written = GetEnvironmentVariableW(name, value.data(), size);
    if (written == 0 || written >= size) {
        return std::nullopt;
    }
    value.resize(written);
    return std::filesystem::path(value);
}

#else

class EchoOff {
  public:
    EchoOff() {
        if (isatty(STDIN_FILENO) != 0 && tcgetattr(STDIN_FILENO, &saved_) == 0) {
            termios quiet = saved_;
            quiet.c_lflag &= ~static_cast<tcflag_t>(ECHO);
            active_ = tcsetattr(STDIN_FILENO, TCSAFLUSH, &quiet) == 0;
        }
    }
    EchoOff(const EchoOff&) = delete;
    EchoOff& operator=(const EchoOff&) = delete;
    EchoOff(EchoOff&&) = delete;
    EchoOff& operator=(EchoOff&&) = delete;
    ~EchoOff() {
        if (active_) {
            (void)tcsetattr(STDIN_FILENO, TCSAFLUSH, &saved_);
        }
    }

    [[nodiscard]] bool active() const noexcept { return active_; }

  private:
    termios saved_{};
    bool active_ = false;
};

std::optional<std::filesystem::path> env_path(const char* name) {
    // Read once at startup, before any other thread exists.
    const char* value = std::getenv(name); // NOLINT(concurrency-mt-unsafe)
    if (value == nullptr || *value == '\0') {
        return std::nullopt;
    }
    return std::filesystem::path(value);
}

#endif

std::optional<SecureString> read_answer(std::string_view prompt, bool echo);

} // namespace

TerminalConsole::TerminalConsole() {
#ifdef _WIN32
    (void)SetConsoleOutputCP(CP_UTF8);
#endif
    // Unbuffered, so stdio keeps no extra copy of what's typed at a prompt.
    (void)std::setvbuf(stdin, nullptr, _IONBF, 0);
}

void TerminalConsole::out(std::string_view text) {
    write(stdout, text);
}

void TerminalConsole::err(std::string_view text) {
    write(stderr, text);
}

std::optional<SecureString> TerminalConsole::read_line(std::string_view prompt) {
    return read_answer(prompt, true);
}

std::optional<SecureString> TerminalConsole::read_secret(std::string_view prompt) {
    return read_answer(prompt, false);
}

namespace {

std::optional<SecureString> read_answer(std::string_view prompt, bool echo) {
    write(stderr, prompt);
#ifdef _WIN32
    auto* const input = GetStdHandle(STD_INPUT_HANDLE);
    if (!is_console(input)) {
        return read_stream_line();
    }
    if (echo) {
        return read_console_line(input);
    }
    const EchoOff quiet(input);
    std::optional<SecureString> answer = read_console_line(input);
#else
    if (echo) {
        return read_stream_line();
    }
    const EchoOff quiet;
    std::optional<SecureString> answer = read_stream_line();
#endif
    if (quiet.active()) {
        write(stderr, "\n"); // the Enter key wasn't echoed
    }
    return answer;
}

} // namespace

std::vector<std::string> utf8_arguments(int argc, char** argv) {
#ifdef _WIN32
    (void)argc;
    (void)argv;
    int count = 0;
    struct LocalFreeDeleter {
        void operator()(LPWSTR* p) const noexcept { (void)LocalFree(p); }
    };
    const std::unique_ptr<LPWSTR, LocalFreeDeleter> wide(CommandLineToArgvW(GetCommandLineW(), &count));
    if (!wide || count < 1) {
        throw std::runtime_error("can't read the command line");
    }
    std::vector<std::string> args;
    for (const wchar_t* arg : std::span(wide.get(), static_cast<std::size_t>(count)).subspan(1)) {
        args.push_back(to_utf8(arg));
    }
    return args;
#else
    if (argc < 1) {
        return {};
    }
    const std::span<char*> all(argv, static_cast<std::size_t>(argc));
    return {all.begin() + 1, all.end()};
#endif
}

std::filesystem::path default_vault_path() {
    const std::string_view file = "vault.ckvault";
#ifdef _WIN32
    if (auto custom = env_path(L"CK_VAULT")) {
        return *custom;
    }
    if (auto local = env_path(L"LOCALAPPDATA")) {
        return *local / "CipherKeeper" / file;
    }
#else
    if (auto custom = env_path("CK_VAULT")) {
        return *custom;
    }
#ifdef __APPLE__
    if (auto home = env_path("HOME")) {
        return *home / "Library" / "Application Support" / "CipherKeeper" / file;
    }
#else
    if (auto data = env_path("XDG_DATA_HOME")) {
        return *data / "cipherkeeper" / file;
    }
    if (auto home = env_path("HOME")) {
        return *home / ".local" / "share" / "cipherkeeper" / file;
    }
#endif
#endif
    return {file};
}

} // namespace ck::cli
