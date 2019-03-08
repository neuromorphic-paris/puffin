#include "../source/puffin.hpp"
#include <chrono>
#include <iostream>

int main(int argc, char* argv[]) {
    auto server = puffin::make_server(
        8080,
        [](std::size_t id, const std::string& url) {
            std::cout << id << " connected with url '" + url + "'" << std::endl;
            return puffin::string_to_message("welcome");
        },
        [](std::size_t id, const puffin::message& message) {
            std::cout << id << " sent the message '" << std::string(message.bytes.begin(), message.bytes.end()) << "'"
                      << std::endl;
        },
        [](std::size_t id) { std::cout << id << " disconnected" << std::endl; });
    for (;;) {
        server->broadcast(puffin::string_to_message("ping"));
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    return 0;
}
