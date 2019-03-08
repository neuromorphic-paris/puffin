![puffin](banner.png "The Puffin banner")

# install

## clone

Within a Git repository, run the commands:

```sh
mkdir -p third_party
cd third_party
git submodule add https://github.com/neuromorphic-paris/puffin.git
```

On __Linux__, the application must link to pthread.

# user guide

The following example implements a Websocket server listening for connections on port `8080`, and sending the string `"ping"` to all its clients once every second:
```cpp
#include "third_party/puffin/source/puffin.hpp"
#include <chrono>

int main(int argc, char* argv[]) {
    auto server = puffin::make_server(
        8080, // listening port
        [](std::size_t, const std::string&) {       // connection callback
            return puffin::message{};               // first response
        },
        [](std::size_t, const puffin::message&) {}, // message callback
        [](std::size_t) {});                        // disconnection callback
    for (;;) {
        server->broadcast(puffin::string_to_message("ping"));
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    return 0;
}
```

`puffin::message` and `puffin::string_to_message` have the following signature:
```cpp
/// puffin implements a Websocket server.
namespace puffin {
    /// message contains data bytes and type information.
    struct message {
        std::vector<uint8_t> bytes;
        bool is_string;
    };

    /// string_to_message converts a string to a socket message.
    message string_to_message(const std::string& content);
}
```

`puffin::make_server` has the following signature:
```cpp
namespace puffin {
    /// make_server creates a server from functors.
    template <typename HandleConnection, typename HandleMessage, typename HandleDisconnections>
    std::unique_ptr<server> make_server(
        uint16_t port,
        HandleConnection handle_connection,
        HandleMessage handle_message,
        HandleDisconnection handle_disconnection);
}
```
- `port` is the TCP port to listen to.
- The expression `handle_connection(id, url)`, where `id` is a is a `std::size_t` integer and `url` is a `std::string` object, must be valid and return a `puffin::message` object. `handle_connection` is called when a new client starts a connection. The returned message is sent to the newly connected client before any other message. If this message is empty, it is not sent.
- The expression `handle_message(id, message)`, where `id` is a `std::size_t` integer and `message` is a `puffin::message` object, must be valid. `handle_message` is called when a client sends a message.
- The expression `handle_disconnection(id)`, where `id` is a `std::size_t` integer, must be valid. `handle_disconnection` is called when a client is disconnected.
- `certificate_filename` and `key_filename` are the paths (absolute or relative to the executable) to the SSL certificate and key files, respectively. When provided, `make_server` returns a secure WebSocket server instead of a standard WebSocket server.

`handle_connection`, `handle_message` and `handle_disconnection` are always called from the same thread. Keeping track of connected clients by adding and removing them from a container can be done in the bodies of `handle_connection` and `handle_disconnection` without locks. However, this calling thread is not the main thread.

`puffin::server` has the following signature:
```cpp
/// puffin implements a Websocket server.
namespace puffin {
    /// server manages the TCP connection and Websocket protocol (version 13).
    class server {
        /// broadcast sends a message to every connected client.
        virtual void broadcast(const message& socket_message);

        /// send sends a message to the client with the gven id.
        virtual void send(std::size_t id, const message& socket_message);

        /// close terminates the connection with a client.
        virtual void close(std::size_t id);
    }
}
```
The methods exposed by `puffin::server` are thread-safe. Calls to `send_to` and `close` with an unknown client id do not throw exceptions. A server closes the connections to its clients when it goes out of scope.

The following example implements a more complex server which prints client connections, messages and disconnections events to standard output. On connection, clients are sent the message `"welcome"`. When a client sends a message, the server sends the message `"pong"` back.
```cpp
#include "third_party/puffin/source/puffin.hpp"
#include <chrono>
#include <iostream>

int main(int argc, char* argv[]) {
    std::unique_ptr<puffin::server> server; // declare server first to use 'send' in a callback
    server = puffin::make_server(
        8080,
        [](std::size_t id, const std::string& url) {
            std::cout << id << " connected with url '" << url << "'" << std::endl;
            return puffin::string_to_message("welcome");
        },
        [&](std::size_t id, const puffin::message& message) {
            std::cout << id << " sent the message '" << std::string(message.bytes.begin(), message.bytes.end()) << "'"
                      << std::endl;
            server->send(id, puffin::string_to_message("pong"));
        },
        [](std::size_t id) {
            std::cout << id << " disconnected" << std::endl;
        });
    for (;;) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    return 0;
}
```

# contribute

## development dependencies

### Debian / Ubuntu

Open a terminal and run:
```sh
sudo apt install premake4 # cross-platform build configuration
sudo apt install clang-format # formatting tool
```

### macOS

Open a terminal and run:
```sh
brew install premake # cross-platform build configuration
brew install clang-format # formatting tool
```

### Windows

Download and install:
- [Visual Studio Community](https://visualstudio.microsoft.com/vs/community/). Select at least __Desktop development with C++__ when asked.
- [git](https://git-scm.com)
- [premake 4.x](https://premake.github.io/download.html). In order to use it from the command line, the *premake4.exe* executable must be copied to a directory in your path. After downloading and decompressing *premake-4.4-beta5-windows.zip*, run from the command line:
```sh
copy "%userprofile%\Downloads\premake-4.4-beta5-windows\premake4.exe" "%userprofile%\AppData\Local\Microsoft\WindowsApps"
```

## test

To test the library, run from the *puffin* directory:
```sh
premake4 gmake
cd build
make
cd release
./puffin
```

Then, open *test/puffin.html* with a web browser. Open the developer tools to see the logged messages.

__Windows__ users must run `premake4 vs2010` instead, and open the generated solution with Visual Studio.

After changing the code, format the source files by running from the *puffin* directory:
```sh
clang-format -i source/puffin.hpp
clang-format -i test/puffin.cpp
```

__Windows__ users must run *Edit* > *Advanced* > *Format Document* from the Visual Studio menu instead.

# license

See the [LICENSE](LICENSE.txt) file for license rights and limitations (GNU GPLv3).
