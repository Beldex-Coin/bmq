
add_subdirectory(Catch2)

add_executable(tests
    main.cpp
    test_address.cpp
    test_batch.cpp
    test_bt.cpp
    test_connect.cpp
    test_commands.cpp
    test_encoding.cpp
    test_failures.cpp
    test_inject.cpp
    test_requests.cpp
    test_tagged_threads.cpp
    test_timer.cpp
)

find_package(Threads)

target_link_libraries(tests Catch2::Catch2 bmq Threads::Threads)

set_target_properties(tests PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
)

add_custom_target(check COMMAND tests)
