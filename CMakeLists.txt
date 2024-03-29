cmake_minimum_required(VERSION 3.20)

set(PROJECT_DESCRIPTION "Client for https://ucentral.in.tum.de to unlock your device for printing.")
project("ucentral-cli" 
            VERSION 1.0.0
            DESCRIPTION "${PROJECT_DESCRIPTION}"
            HOMEPAGE_URL "https://github.com/COM8/ucentral-cli")
set(VERSION_NAME "dev")

set(CMAKE_CXX_STANDARD 20)

macro(ucentral_cli_option OPTION_NAME OPTION_TEXT OPTION_DEFAULT)
    option(${OPTION_NAME} ${OPTION_TEXT} ${OPTION_DEFAULT})
    if(DEFINED ENV{${OPTION_NAME}})
        # Allow setting the option through an environment variable
        set(${OPTION_NAME} $ENV{${OPTION_NAME}})
    endif()
    if(${OPTION_NAME})
        add_definitions(-D${OPTION_NAME})
    endif()
    message(STATUS "  ${OPTION_NAME}: ${${OPTION_NAME}}")
endmacro()

message(STATUS "ucentral client options")
message(STATUS "=======================================================")
ucentral_cli_option(UCENTRAL_CLI_STATIC_ANALYZE "Set to ON to enable the GCC 10 static analysis. If enabled, UCENTRAL_CLI_ENABLE_LINTING has to be disabled." OFF)
ucentral_cli_option(UCENTRAL_CLI_ENABLE_LINTING "Set to ON to enable clang linting. If enabled, UCENTRAL_CLI_STATIC_ANALYZE has to be disabled." ON)
message(STATUS "=======================================================")

list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)
include(sanitizer)
include(gcc_analyze)
include(clear_variable)
include(FetchContent)

if(UCENTRAL_CLI_ENABLE_LINTING)
    message(STATUS "Enabling linting")
    include(clang-tidy)
else()
    message(STATUS "Linting is disabled")
endif()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wpedantic")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")

add_executable(ucentral-ui main.cpp)

# Disable linting for fetch content projects
clear_variable(DESTINATION CMAKE_CXX_CLANG_TIDY BACKUP CMAKE_CXX_CLANG_TIDY_BKP)

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

restore_variable(DESTINATION CMAKE_CXX_CLANG_TIDY BACKUP CMAKE_CXX_CLANG_TIDY_BKP)

target_link_libraries(ucentral-ui PRIVATE cpr::cpr nlohmann_json::nlohmann_json keychain)

include(GNUInstallDirs)
install(TARGETS ucentral-ui RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
