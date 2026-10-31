find_package(Qt6 REQUIRED COMPONENTS Widgets)
qt_standard_project_setup()

qt_add_executable(cipherkeeper_gui WIN32
    src/main.cpp
)
set_target_properties(cipherkeeper_gui PROPERTIES OUTPUT_NAME CipherKeeper)
target_link_libraries(cipherkeeper_gui PRIVATE cipherkeeper::core Qt6::Widgets ck_options)
