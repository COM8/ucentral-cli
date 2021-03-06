#include "cpr/api.h"
#include "cpr/body.h"
#include "cpr/cookies.h"
#include "cpr/multipart.h"
#include "cpr/payload.h"
#include <cstddef>
#include <cstdlib>
#include <iostream>
#include <nlohmann/json.hpp>
#include <optional>
#include <regex>
#include <string>
#include <cpr/cpr.h>
#include <keychain/keychain.h>
#include <termios.h>
#include <unistd.h>

std::string extract_user_secret(const std::string& data) {
    std::regex secretRegex("printman\\.(\\d|[a-f]|[A-F]){10,}");
    std::regex_iterator matches = std::sregex_iterator(data.begin(), data.end(), secretRegex);
    if (matches == std::sregex_iterator()) {
        std::cerr << "No user secret found!\n";
        return "";
    }
    return matches->str();
}

std::string get_user_secret(const std::string& sid) {
    cpr::Response r = cpr::Get(cpr::Url{"https://ucentral.in.tum.de/cgi-bin/printman.cgi"}, cpr::Cookies{{"sid", sid}});
    if (r.status_code == 200) {
        try {
            return extract_user_secret(r.text);
        } catch (const std::exception& e) {
            std::cerr << "Failed to get user secret with: " << e.what() << '\n';
        }
    } else {
        std::cerr << "Failed to get user secret with: " << r.status_code << ' ' << r.error.message << '\n';
    }
    return "";
}

std::string perform_login(const std::string& user, const std::string& password) {
    cpr::Multipart form{{"user", user}, {"pwd", password}, {"login", "Login"}, {"request", ""}};
    cpr::Response r = cpr::Post(cpr::Url{"https://ucentral.in.tum.de/cgi-bin/login.cgi"}, std::move(form));
    if (r.status_code == 200) {
        try {
            return r.cookies["sid"];
        } catch (const std::exception& e) {
            std::cerr << "Failed to get info with: " << e.what() << '\n';
        }
    } else {
        std::cerr << "Failed to get info with: " << r.status_code << ' ' << r.error.message << '\n';
    }
    return "";
}

std::optional<nlohmann::json> get_info() {
    cpr::Response r = cpr::Get(cpr::Url{"https://print.in.tum.de:8443/ipdb/ipdb-user.cgi"});
    if (r.status_code == 200) {
        try {
            std::cout << "[GET INFO]: " << r.text << '\n';
            return nlohmann::json::parse(r.text);
        } catch (const std::exception& e) {
            std::cerr << "Failed to get info with: " << e.what() << '\n';
        }
    } else {
        std::cerr << "Failed to get info with: " << r.status_code << ' ' << r.error.message << '\n';
    }
    return std::nullopt;
}

std::optional<nlohmann::json> get_jobs() {
    cpr::Response r = cpr::Get(cpr::Url{"https://print.in.tum.de:8443/ipdb/ipdb-jobs.cgi"});
    if (r.status_code == 200) {
        try {
            std::cout << "[GET JOBS]: " << r.text << '\n';
            return nlohmann::json::parse(r.text);
        } catch (const std::exception& e) {
            std::cerr << "Failed to get jobs with: " << e.what() << '\n';
        }
    } else {
        std::cerr << "Failed to get jobs with: " << r.status_code << ' ' << r.error.message << '\n';
    }
    return std::nullopt;
}

std::optional<nlohmann::json> bind_ip(const std::string& userName, const std::string& userSecret, const std::string& ip) {
    nlohmann::json body{
        {"user", userName + "@in.tum.de"},
        {"usersecret", userSecret},
        {"ip", ip}};

    cpr::Response r = cpr::Post(cpr::Url{"https://print.in.tum.de:8443/ipdb/ipdb-user.cgi"}, cpr::Body(body.dump()));
    if (r.status_code == 200) {
        try {
            std::cout << "[BIND IP]: " << r.text << '\n';
            return nlohmann::json::parse(r.text);
        } catch (const std::exception& e) {
            std::cerr << "Failed to bind ip with: " << e.what() << '\n';
        }
    } else {
        std::cerr << "Failed to bind ip with: " << r.status_code << ' ' << r.error.message << '\n';
    }
    return std::nullopt;
}

void print_info(const nlohmann::json& info) {
    std::string ip;
    info.at("client_ip").get_to(ip);
    std::cout << "IP: " << ip << '\n';
    bool dynamicIP = false;
    info.at("dynip").get_to(dynamicIP);
    std::cout << "Dynamic IP: " << dynamicIP << '\n';
    std::string user;
    if (!info.at("user").is_null()) {
        info.at("user").get_to(user);
    }
    std::cout << "User: " << user << '\n';
    std::string legicCardId;
    if (!info.at("user_legicID").is_null()) {
        info.at("user_legicID").get_to(legicCardId);
    }
    std::cout << "Legic Card ID: " << legicCardId << '\n';
    int remaining = -1;
    if (info.contains("remaining")) {
        info.at("remaining").get_to(remaining);
    }
    std::cout << "Remaining: " << remaining << '\n';
    bool isSynced = false;
    info.at("is_struk_synced").get_to(isSynced);
    std::cout << "Is Synced: " << isSynced << '\n';
    bool bindable = false;
    info.at("bindable").get_to(bindable);
    std::cout << "Bindable: " << bindable << '\n';
}

bool load_password(const std::string& user, std::string* password) {
    keychain::Error error{};
    *password = keychain::getPassword("ucentral-cli", "ucentral", user, error);
    if (error && error.type != keychain::ErrorType::NotFound) {
        std::cerr << "Failed to load password for '" << user << "' with: " << error.message << '\n';
        return false;
    }
    return true;
}

bool store_password(const std::string& user, const std::string& password) {
    keychain::Error error{};
    keychain::setPassword("ucentral-cli", "ucentral", user, password, error);
    if (error) {
        std::cerr << "Failed to store password with: " << error.message << '\n';
        return false;
    }
    return true;
}

void set_stdin_echo(bool enable) {
    termios tty{};
    tcgetattr(STDIN_FILENO, &tty);
    if (!enable) {
        tty.c_lflag &= ~ECHO;
    } else {
        tty.c_lflag |= ECHO;
    }
    (void) tcsetattr(STDIN_FILENO, TCSANOW, &tty);
}

std::string read_password() {
    std::cout << "Password: ";
    std::string password;
    set_stdin_echo(false);
    std::cin >> password;
    set_stdin_echo(true);
    std::cout << '\n';
    return password;
}

// NOLINTNEXTLINE (bugprone-exception-escape)
int main(int argC, char** argV) {
    std::string userName;
    std::string password;
    if (argC == 2) {
        // NOLINTNEXTLINE (cppcoreguidelines-pro-bounds-pointer-arithmetic)
        userName = argV[1];
        if (!load_password(userName, &password)) {
            password = read_password();
            if (password.empty()) {
                std::cerr << "An empty password is not allowed!\n";
                return EXIT_FAILURE;
            }
            std::cout << "Password loaded from system keyring.\n";
        }
    } else if (argC == 3) {
        // NOLINTNEXTLINE (cppcoreguidelines-pro-bounds-pointer-arithmetic)
        userName = argV[1];
        // NOLINTNEXTLINE (cppcoreguidelines-pro-bounds-pointer-arithmetic)
        password = argV[2];
    } else {
        // NOLINTNEXTLINE (cppcoreguidelines-pro-bounds-pointer-arithmetic)
        std::cerr << argV[0] << " <userName> [<password>]\n";
        return EXIT_FAILURE;
    }

    const std::string sid = perform_login(userName, password);
    if (sid.empty()) {
        std::cerr << "Login failed!\n";
        return EXIT_FAILURE;
    }
    std::cout << "New session ID: " << sid << '\n';

    const std::string userSecret = get_user_secret(sid);
    if (userSecret.empty()) {
        return EXIT_FAILURE;
    }
    std::cout << "New user secret: " << userSecret << '\n';

    if (!store_password(userName, password)) {
        std::cerr << "Failed to store password in your system keyring!\n";
        return EXIT_FAILURE;
    }
    std::cout << "Password stored to system keyring.\n";

    std::optional<nlohmann::json> info = get_info();
    if (!info) {
        return EXIT_FAILURE;
    }

    print_info(*info);
    bool bindable = false;
    info->at("bindable").get_to(bindable);
    if (!bindable) {
        std::cerr << "Not bindable!\n";
        return EXIT_FAILURE;
    }

    if (!info->at("user").is_null()) {
        std::string user;
        info->at("user").get_to(user);
        int remaining = -1;
        if (info->contains("remaining")) {
            info->at("remaining").get_to(remaining);
        }
        std::cerr << "Already bound to '" << user << "' for the next " << remaining << "s.\n";
        return EXIT_FAILURE;
    }

    std::string ip;
    info->at("client_ip").get_to(ip);
    std::optional<nlohmann::json> bind = bind_ip(userName, userSecret, ip);
    if (!bind) {
        return EXIT_FAILURE;
    }

    bool success = false;
    if (bind->contains("success")) {
        bind->at("success").get_to(success);
    }
    if (!success) {
        std::cerr << "Binding was not successful!\n";
        return EXIT_FAILURE;
    }
    std::cout << "Success!\n";
    return EXIT_SUCCESS;
}