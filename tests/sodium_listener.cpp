#include <cipherkeeper/core.hpp>

#include <catch2/reporters/catch_reporter_event_listener.hpp>
#include <catch2/reporters/catch_reporter_registrars.hpp>

#include <stdexcept>

namespace {

// Initializes libsodium once before any test runs, as the app does at startup.
class SodiumInitListener : public Catch::EventListenerBase {
  public:
    using Catch::EventListenerBase::EventListenerBase;

    void testRunStarting(const Catch::TestRunInfo& /*info*/) override {
        if (!ck::initialize()) {
            throw std::runtime_error("libsodium failed to initialize");
        }
    }
};

} // namespace

CATCH_REGISTER_LISTENER(SodiumInitListener)
