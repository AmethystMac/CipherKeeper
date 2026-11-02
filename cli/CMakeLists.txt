# The commands live in a library so tests can run them with a scripted console. main.cpp and the real terminal
# (no-echo input, UTF-8 arguments) are the only parts that aren't tested.
add_library(cipherkeeper_cli_lib STATIC
    src/cli.cpp
    src/commands.cpp
    src/item_fields.cpp
)
target_include_directories(cipherkeeper_cli_lib PUBLIC src)
target_link_libraries(cipherkeeper_cli_lib PUBLIC cipherkeeper::core PRIVATE ck_options)

add_executable(cipherkeeper_cli
    src/main.cpp
    src/terminal.cpp
)
set_target_properties(cipherkeeper_cli PROPERTIES OUTPUT_NAME ck)
target_link_libraries(cipherkeeper_cli PRIVATE cipherkeeper_cli_lib ck_options)
if(WIN32)
    # CommandLineToArgvW, for UTF-8 arguments
    target_link_libraries(cipherkeeper_cli PRIVATE shell32)
endif()
