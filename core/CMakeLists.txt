find_package(unofficial-sodium CONFIG REQUIRED)
find_package(unofficial-sqlite3 CONFIG REQUIRED)

add_library(cipherkeeper_core
    src/core.cpp
)
add_library(cipherkeeper::core ALIAS cipherkeeper_core)

target_include_directories(cipherkeeper_core PUBLIC include)
target_compile_definitions(cipherkeeper_core PRIVATE CK_VERSION="${PROJECT_VERSION}")
target_link_libraries(cipherkeeper_core
    PRIVATE
        unofficial-sodium::sodium
        unofficial::sqlite3::sqlite3
        ck_options
)
