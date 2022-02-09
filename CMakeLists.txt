cmake_minimum_required(VERSION 3.20)

set(PROJECT_DESCRIPTION "UWPX XMPP push server.")
project("Client for https://ucentral.in.tum.de to unlock your device for printing." 
            VERSION 1.0.0
            DESCRIPTION "${PROJECT_DESCRIPTION}"
            HOMEPAGE_URL "https://github.com/COM8/ucentral-cli")
set(VERSION_NAME "dev")

set(CMAKE_CXX_STANDARD 20)

add_executable(ucentral-ui main.cpp)

if(WIN32) # Install dlls in the same directory as the executable on Windows
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
endif()

include(FetchContent)
set(CPR_FORCE_USE_SYSTEM_CURL ON)
FetchContent_Declare(cpr GIT_REPOSITORY https://github.com/libcpr/cpr.git
                         GIT_TAG beb9e98806bb84bcc130a2cebfbcbbc6ce62b335) # The commit hash for 1.7.2. Replace with the latest from: https://github.com/libcpr/cpr/releases
FetchContent_MakeAvailable(cpr)

FetchContent_Declare(json GIT_REPOSITORY https://github.com/nlohmann/json.git
                          GIT_TAG v3.10.5)
FetchContent_MakeAvailable(json)

FetchContent_Declare(keychain GIT_REPOSITORY https://github.com/hrantzsch/keychain.git
                          GIT_TAG v1.2.0)
FetchContent_MakeAvailable(keychain)

target_link_libraries(ucentral-ui PRIVATE cpr::cpr nlohmann_json::nlohmann_json keychain)

include(GNUInstallDirs)
install(TARGETS ucentral-ui RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
