add_executable(cipherkeeper_cli
    src/main.cpp
)
set_target_properties(cipherkeeper_cli PROPERTIES OUTPUT_NAME ck)
target_link_libraries(cipherkeeper_cli PRIVATE cipherkeeper::core ck_options)
