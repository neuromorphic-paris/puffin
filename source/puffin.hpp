#pragma once

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <memory>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <Ws2tcpip.h>
#include <winsock2.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#define PUFFIN_F(b, c, d) ((((c) ^ (d)) & (b)) ^ (d))
#define PUFFIN_G(b, c, d) ((b) ^ (c) ^ (d))
#define PUFFIN_H(b, c, d) (((b) & (c)) | (((b) | (c)) & (d)))
#define PUFFIN_ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define PUFFIN_R(f, k, v, w, x, y, z, i)                                                                               \
    {                                                                                                                  \
        (v) = PUFFIN_ROTATE_LEFT(w, 5) + f(x, y, z) + (v) + (i) + (k);                                                 \
        (x) = PUFFIN_ROTATE_LEFT(x, 30);                                                                               \
    }
#define PUFFIN_R1(v, w, x, y, z, i) PUFFIN_R(PUFFIN_F, 0x5a827999ul, v, w, x, y, z, i)
#define PUFFIN_R2(v, w, x, y, z, i) PUFFIN_R(PUFFIN_G, 0x6ed9eba1ul, v, w, x, y, z, i)
#define PUFFIN_R3(v, w, x, y, z, i) PUFFIN_R(PUFFIN_H, 0x8f1bbcdcul, v, w, x, y, z, i)
#define PUFFIN_R4(v, w, x, y, z, i) PUFFIN_R(PUFFIN_G, 0xca62c1d6ul, v, w, x, y, z, i)
#define PUFFIN_WUPDATE(p, q, r, s)                                                                                     \
    {                                                                                                                  \
        (p) = ((q) ^ (r) ^ (s) ^ (p));                                                                                 \
        (p) = PUFFIN_ROTATE_LEFT(p, 1);                                                                                \
    }

/// puffin implements a Websocket server.
namespace puffin {
#ifdef _WIN32
    using socket_file_descriptor_t = uint32_t;
#else
    using socket_file_descriptor_t = int32_t;
#endif

    /// sha1 is an implementation  of the sha1 cryptographic algorithm.
    /// OutputIterator must iterate over a 20 bytes container.
    template <typename InputIterator, typename OutputIterator>
    inline void sha1(InputIterator input_begin, InputIterator input_end, OutputIterator output_begin) {
        auto round = [](std::array<uint32_t, 5> state, const std::array<uint8_t, 64>& block) {
            auto a = std::get<0>(state);
            auto b = std::get<1>(state);
            auto c = std::get<2>(state);
            auto d = std::get<3>(state);
            auto e = std::get<4>(state);
            auto w0 = htonl(*reinterpret_cast<const uint32_t*>(block.data()));
            auto w1 = htonl(*reinterpret_cast<const uint32_t*>(block.data() + 4));
            auto w2 = htonl(*reinterpret_cast<const uint32_t*>(block.data() + 8));
            auto w3 = htonl(*reinterpret_cast<const uint32_t*>(block.data() + 12));
            auto w4 = htonl(*reinterpret_cast<const uint32_t*>(block.data() + 16));
            auto w5 = htonl(*reinterpret_cast<const uint32_t*>(block.data() + 20));
            auto w6 = htonl(*reinterpret_cast<const uint32_t*>(block.data() + 24));
            auto w7 = htonl(*reinterpret_cast<const uint32_t*>(block.data() + 28));
            auto w8 = htonl(*reinterpret_cast<const uint32_t*>(block.data() + 32));
            auto w9 = htonl(*reinterpret_cast<const uint32_t*>(block.data() + 36));
            auto w10 = htonl(*reinterpret_cast<const uint32_t*>(block.data() + 40));
            auto w11 = htonl(*reinterpret_cast<const uint32_t*>(block.data() + 44));
            auto w12 = htonl(*reinterpret_cast<const uint32_t*>(block.data() + 48));
            auto w13 = htonl(*reinterpret_cast<const uint32_t*>(block.data() + 52));
            auto w14 = htonl(*reinterpret_cast<const uint32_t*>(block.data() + 56));
            auto w15 = htonl(*reinterpret_cast<const uint32_t*>(block.data() + 60));
            PUFFIN_R1(e, a, b, c, d, w0);
            PUFFIN_R1(d, e, a, b, c, w1);
            PUFFIN_R1(c, d, e, a, b, w2);
            PUFFIN_R1(b, c, d, e, a, w3);
            PUFFIN_R1(a, b, c, d, e, w4);
            PUFFIN_R1(e, a, b, c, d, w5);
            PUFFIN_R1(d, e, a, b, c, w6);
            PUFFIN_R1(c, d, e, a, b, w7);
            PUFFIN_R1(b, c, d, e, a, w8);
            PUFFIN_R1(a, b, c, d, e, w9);
            PUFFIN_R1(e, a, b, c, d, w10);
            PUFFIN_R1(d, e, a, b, c, w11);
            PUFFIN_R1(c, d, e, a, b, w12);
            PUFFIN_R1(b, c, d, e, a, w13);
            PUFFIN_R1(a, b, c, d, e, w14);
            PUFFIN_R1(e, a, b, c, d, w15);
            PUFFIN_WUPDATE(w0, w13, w8, w2);
            PUFFIN_R1(d, e, a, b, c, w0);
            PUFFIN_WUPDATE(w1, w14, w9, w3);
            PUFFIN_R1(c, d, e, a, b, w1);
            PUFFIN_WUPDATE(w2, w15, w10, w4);
            PUFFIN_R1(b, c, d, e, a, w2);
            PUFFIN_WUPDATE(w3, w0, w11, w5);
            PUFFIN_R1(a, b, c, d, e, w3);
            PUFFIN_WUPDATE(w4, w1, w12, w6);
            PUFFIN_R2(e, a, b, c, d, w4);
            PUFFIN_WUPDATE(w5, w2, w13, w7);
            PUFFIN_R2(d, e, a, b, c, w5);
            PUFFIN_WUPDATE(w6, w3, w14, w8);
            PUFFIN_R2(c, d, e, a, b, w6);
            PUFFIN_WUPDATE(w7, w4, w15, w9);
            PUFFIN_R2(b, c, d, e, a, w7);
            PUFFIN_WUPDATE(w8, w5, w0, w10);
            PUFFIN_R2(a, b, c, d, e, w8);
            PUFFIN_WUPDATE(w9, w6, w1, w11);
            PUFFIN_R2(e, a, b, c, d, w9);
            PUFFIN_WUPDATE(w10, w7, w2, w12);
            PUFFIN_R2(d, e, a, b, c, w10);
            PUFFIN_WUPDATE(w11, w8, w3, w13);
            PUFFIN_R2(c, d, e, a, b, w11);
            PUFFIN_WUPDATE(w12, w9, w4, w14);
            PUFFIN_R2(b, c, d, e, a, w12);
            PUFFIN_WUPDATE(w13, w10, w5, w15);
            PUFFIN_R2(a, b, c, d, e, w13);
            PUFFIN_WUPDATE(w14, w11, w6, w0);
            PUFFIN_R2(e, a, b, c, d, w14);
            PUFFIN_WUPDATE(w15, w12, w7, w1);
            PUFFIN_R2(d, e, a, b, c, w15);
            PUFFIN_WUPDATE(w0, w13, w8, w2);
            PUFFIN_R2(c, d, e, a, b, w0);
            PUFFIN_WUPDATE(w1, w14, w9, w3);
            PUFFIN_R2(b, c, d, e, a, w1);
            PUFFIN_WUPDATE(w2, w15, w10, w4);
            PUFFIN_R2(a, b, c, d, e, w2);
            PUFFIN_WUPDATE(w3, w0, w11, w5);
            PUFFIN_R2(e, a, b, c, d, w3);
            PUFFIN_WUPDATE(w4, w1, w12, w6);
            PUFFIN_R2(d, e, a, b, c, w4);
            PUFFIN_WUPDATE(w5, w2, w13, w7);
            PUFFIN_R2(c, d, e, a, b, w5);
            PUFFIN_WUPDATE(w6, w3, w14, w8);
            PUFFIN_R2(b, c, d, e, a, w6);
            PUFFIN_WUPDATE(w7, w4, w15, w9);
            PUFFIN_R2(a, b, c, d, e, w7);
            PUFFIN_WUPDATE(w8, w5, w0, w10);
            PUFFIN_R3(e, a, b, c, d, w8);
            PUFFIN_WUPDATE(w9, w6, w1, w11);
            PUFFIN_R3(d, e, a, b, c, w9);
            PUFFIN_WUPDATE(w10, w7, w2, w12);
            PUFFIN_R3(c, d, e, a, b, w10);
            PUFFIN_WUPDATE(w11, w8, w3, w13);
            PUFFIN_R3(b, c, d, e, a, w11);
            PUFFIN_WUPDATE(w12, w9, w4, w14);
            PUFFIN_R3(a, b, c, d, e, w12);
            PUFFIN_WUPDATE(w13, w10, w5, w15);
            PUFFIN_R3(e, a, b, c, d, w13);
            PUFFIN_WUPDATE(w14, w11, w6, w0);
            PUFFIN_R3(d, e, a, b, c, w14);
            PUFFIN_WUPDATE(w15, w12, w7, w1);
            PUFFIN_R3(c, d, e, a, b, w15);
            PUFFIN_WUPDATE(w0, w13, w8, w2);
            PUFFIN_R3(b, c, d, e, a, w0);
            PUFFIN_WUPDATE(w1, w14, w9, w3);
            PUFFIN_R3(a, b, c, d, e, w1);
            PUFFIN_WUPDATE(w2, w15, w10, w4);
            PUFFIN_R3(e, a, b, c, d, w2);
            PUFFIN_WUPDATE(w3, w0, w11, w5);
            PUFFIN_R3(d, e, a, b, c, w3);
            PUFFIN_WUPDATE(w4, w1, w12, w6);
            PUFFIN_R3(c, d, e, a, b, w4);
            PUFFIN_WUPDATE(w5, w2, w13, w7);
            PUFFIN_R3(b, c, d, e, a, w5);
            PUFFIN_WUPDATE(w6, w3, w14, w8);
            PUFFIN_R3(a, b, c, d, e, w6);
            PUFFIN_WUPDATE(w7, w4, w15, w9);
            PUFFIN_R3(e, a, b, c, d, w7);
            PUFFIN_WUPDATE(w8, w5, w0, w10);
            PUFFIN_R3(d, e, a, b, c, w8);
            PUFFIN_WUPDATE(w9, w6, w1, w11);
            PUFFIN_R3(c, d, e, a, b, w9);
            PUFFIN_WUPDATE(w10, w7, w2, w12);
            PUFFIN_R3(b, c, d, e, a, w10);
            PUFFIN_WUPDATE(w11, w8, w3, w13);
            PUFFIN_R3(a, b, c, d, e, w11);
            PUFFIN_WUPDATE(w12, w9, w4, w14);
            PUFFIN_R4(e, a, b, c, d, w12);
            PUFFIN_WUPDATE(w13, w10, w5, w15);
            PUFFIN_R4(d, e, a, b, c, w13);
            PUFFIN_WUPDATE(w14, w11, w6, w0);
            PUFFIN_R4(c, d, e, a, b, w14);
            PUFFIN_WUPDATE(w15, w12, w7, w1);
            PUFFIN_R4(b, c, d, e, a, w15);
            PUFFIN_WUPDATE(w0, w13, w8, w2);
            PUFFIN_R4(a, b, c, d, e, w0);
            PUFFIN_WUPDATE(w1, w14, w9, w3);
            PUFFIN_R4(e, a, b, c, d, w1);
            PUFFIN_WUPDATE(w2, w15, w10, w4);
            PUFFIN_R4(d, e, a, b, c, w2);
            PUFFIN_WUPDATE(w3, w0, w11, w5);
            PUFFIN_R4(c, d, e, a, b, w3);
            PUFFIN_WUPDATE(w4, w1, w12, w6);
            PUFFIN_R4(b, c, d, e, a, w4);
            PUFFIN_WUPDATE(w5, w2, w13, w7);
            PUFFIN_R4(a, b, c, d, e, w5);
            PUFFIN_WUPDATE(w6, w3, w14, w8);
            PUFFIN_R4(e, a, b, c, d, w6);
            PUFFIN_WUPDATE(w7, w4, w15, w9);
            PUFFIN_R4(d, e, a, b, c, w7);
            PUFFIN_WUPDATE(w8, w5, w0, w10);
            PUFFIN_R4(c, d, e, a, b, w8);
            PUFFIN_WUPDATE(w9, w6, w1, w11);
            PUFFIN_R4(b, c, d, e, a, w9);
            PUFFIN_WUPDATE(w10, w7, w2, w12);
            PUFFIN_R4(a, b, c, d, e, w10);
            PUFFIN_WUPDATE(w11, w8, w3, w13);
            PUFFIN_R4(e, a, b, c, d, w11);
            PUFFIN_WUPDATE(w12, w9, w4, w14);
            PUFFIN_R4(d, e, a, b, c, w12);
            PUFFIN_WUPDATE(w13, w10, w5, w15);
            PUFFIN_R4(c, d, e, a, b, w13);
            PUFFIN_WUPDATE(w14, w11, w6, w0);
            PUFFIN_R4(b, c, d, e, a, w14);
            PUFFIN_WUPDATE(w15, w12, w7, w1);
            PUFFIN_R4(a, b, c, d, e, w15);
            return std::array<uint32_t, 5>{
                std::get<0>(state) + a,
                std::get<1>(state) + b,
                std::get<2>(state) + c,
                std::get<3>(state) + d,
                std::get<4>(state) + e,
            };
        };
        const auto size = static_cast<uint64_t>(std::distance(input_begin, input_end)) * 8;
        std::array<uint32_t, 5> state{0x67452301ul, 0xefcdab89ul, 0x98badcfeul, 0x10325476ul, 0xc3d2e1f0ul};
        std::array<uint8_t, 64> block;
        for (;;) {
            if (std::distance(input_begin, input_end) > 64) {
                std::copy(input_begin, std::next(input_begin, 64), block.begin());
                state = round(state, block);
                std::advance(input_begin, 64);
            } else {
                std::copy(input_begin, input_end, block.begin());
                const auto block_size = static_cast<std::size_t>(std::distance(input_begin, input_end));
                if (block_size == 64) {
                    state = round(state, block);
                    block.fill(0);
                    block[0] = 0x80;
                } else if (block_size > 55) {
                    block[block_size] = 0x80;
                    std::fill(std::next(block.begin(), block_size + 1), block.end(), 0);
                    state = round(state, block);
                    block.fill(0);
                } else {
                    block[block_size] = 0x80;
                    std::fill(std::next(block.begin(), block_size + 1), block.end(), 0);
                }
                if (htons(0xff00) == 0xff00) {
                    *reinterpret_cast<uint64_t*>(block.data() + 56) = size;
                } else {
                    *reinterpret_cast<uint32_t*>(block.data() + 56) = htonl(static_cast<uint32_t>(size >> 32));
                    *reinterpret_cast<uint32_t*>(block.data() + 60) = htonl(static_cast<uint32_t>(size & 0xffffffff));
                }
                state = round(state, block);
                input_begin = input_end;
                break;
            }
        }
        for (auto variable : state) {
            variable = htonl(variable);
            *output_begin = static_cast<uint8_t>(variable & 0xff);
            ++output_begin;
            *output_begin = static_cast<uint8_t>((variable >> 8) & 0xff);
            ++output_begin;
            *output_begin = static_cast<uint8_t>((variable >> 16) & 0xff);
            ++output_begin;
            *output_begin = static_cast<uint8_t>((variable >> 24) & 0xff);
            ++output_begin;
        }
    }

    /// message contains data bytes and type information.
    struct message {
        std::vector<uint8_t> bytes;
        bool is_string;
    };

    /// string_to_message converts a string to a socket message.
    inline message string_to_message(const std::string& content) {
        return {std::vector<uint8_t>(content.begin(), content.end()), true};
    }

    /// server manages the TCP connection and Websocket protocol (version 13).
    class server {
        public:
        server() = default;
        server(const server&) = delete;
        server(server&&) = default;
        server& operator=(const server&) = delete;
        server& operator=(server&&) = default;
        virtual ~server() {}

        /// broadcast sends a message to every connected client.
        virtual void broadcast(const message& socket_message) = 0;

        /// send sends a message to the client with the given id.
        virtual void send(std::size_t id, const message& socket_message) = 0;

        /// close terminates the connection with a client.
        virtual void close(std::size_t id) = 0;
    };

    /// specialized_server implements a server with template callbacks.
    template <typename HandleConnection, typename HandleMessage, typename HandleDisconnection>
    class specialized_server : public server {
        public:
        specialized_server(
            uint16_t port,
            HandleConnection handle_connection,
            HandleMessage handle_message,
            HandleDisconnection handle_disconnection) :
            server(),
            _handle_connection(std::forward<HandleConnection>(handle_connection)),
            _handle_message(std::forward<HandleMessage>(handle_message)),
            _handle_disconnection(std::forward<HandleDisconnection>(handle_disconnection)),
            _running(true) {
            _accessing_sockets.clear(std::memory_order_release);
            _accessing_closing.clear(std::memory_order_release);
#ifdef _WIN32
            WSADATA wsa_data;
            WSAStartup(MAKEWORD(1, 1), &wsa_data);
#endif
            _socket_file_descriptor = check_socket(socket(AF_INET, SOCK_STREAM, 0));
            {
                int32_t option = 1;
                check(
                    setsockopt(
                        _socket_file_descriptor,
                        SOL_SOCKET,
                        SO_REUSEADDR,
                        reinterpret_cast<const char*>(&option),
                        sizeof(option)),
                    "enabling local address re-use");
            }
            {
                sockaddr_in address;
                address.sin_family = AF_INET;
                address.sin_addr.s_addr = INADDR_ANY;
                address.sin_port = htons(port);
                check(
                    bind(_socket_file_descriptor, reinterpret_cast<sockaddr*>(&address), sizeof(address)),
                    "binding the socket");
            }
            check(listen(_socket_file_descriptor, SOMAXCONN), "setting the socket to listening mode");
            _loop = std::thread([this]() {
                fd_set sockets_file_descriptor_set;
                timeval timeout;
                std::vector<uint8_t> buffer(1 << 12);
                while (_running.load(std::memory_order_acquire)) {
                    FD_ZERO(&sockets_file_descriptor_set);
                    FD_SET(_socket_file_descriptor, &sockets_file_descriptor_set);
                    socket_file_descriptor_t maximum = _socket_file_descriptor;
                    while (_accessing_closing.test_and_set(std::memory_order_acquire)) {
                    }
                    for (auto socket = _sockets.begin(); socket != _sockets.end();) {
                        if (socket->closing) {
                            socket = erase(socket);
                            continue;
                        } else {
                            if (socket->file_descriptor > maximum) {
                                maximum = socket->file_descriptor;
                            }
                            FD_SET(socket->file_descriptor, &sockets_file_descriptor_set);
                            ++socket;
                        }
                    }
                    _accessing_closing.clear(std::memory_order_release);
                    timeout.tv_sec = 0;
                    timeout.tv_usec = 20000;
                    if (select(maximum + 1, &sockets_file_descriptor_set, nullptr, nullptr, &timeout) <= 0) {
                        continue;
                    }
                    for (auto socket = _sockets.begin(); socket != _sockets.end();) {
                        if (FD_ISSET(socket->file_descriptor, &sockets_file_descriptor_set)) {
                            int64_t read_bytes = 0;
                            read_bytes = recv(socket->file_descriptor, buffer.data(), buffer.size(), 0);
                            if (read_bytes <= 0) {
                                socket = erase(socket);
                            } else {
                                if (socket->ready) {
                                    try {
                                        if (!socket->buffer.empty()) {
                                            buffer.resize(read_bytes);
                                            read_bytes += socket->buffer.size();
                                            buffer.insert(buffer.begin(), socket->buffer.begin(), socket->buffer.end());
                                            socket->buffer.clear();
                                        }
                                        auto begin = buffer.begin();
                                        auto end = std::next(buffer.begin(), read_bytes);
                                        while (begin != end) {
                                            if (socket->mask_index < 4) {
                                                if (std::distance(socket->begin, socket->data.end())
                                                    > std::distance(begin, end)) {
                                                    switch (socket->type) {
                                                        case packet_type::invalid:
                                                            std::advance(socket->begin, std::distance(begin, end));
                                                            break;
                                                        case packet_type::ping:
                                                            std::copy(begin, end, socket->begin);
                                                            std::advance(socket->begin, std::distance(begin, end));
                                                            break;
                                                        default:
                                                            for (; begin != end; ++begin) {
                                                                *(socket->begin) =
                                                                    (*begin) ^ socket->mask[socket->mask_index];
                                                                ++socket->begin;
                                                                socket->mask_index = (socket->mask_index + 1) % 4;
                                                            }
                                                            break;
                                                    }
                                                    break;
                                                } else {
                                                    switch (socket->type) {
                                                        case packet_type::invalid:
                                                            socket->data.clear();
                                                            socket->begin = socket->data.begin();
                                                            socket->mask_index = 4;
                                                            break;
                                                        case packet_type::ping: {
                                                            std::array<uint8_t, 6> header{
                                                                static_cast<uint8_t>(0b10001010),
                                                                static_cast<uint8_t>(0b10000000 | socket->data.size()),
                                                                std::get<0>(socket->mask),
                                                                std::get<1>(socket->mask),
                                                                std::get<2>(socket->mask),
                                                                std::get<3>(socket->mask),
                                                            };
                                                            socket->data.insert(
                                                                socket->data.begin(), header.begin(), header.end());
                                                            write(*socket, socket->data);
                                                            socket->data.clear();
                                                            socket->begin = socket->data.begin();
                                                            socket->mask_index = 4;
                                                            break;
                                                        }
                                                        case packet_type::text:
                                                        case packet_type::binary:
                                                            for (; socket->begin != socket->data.end();
                                                                 ++socket->begin) {
                                                                *(socket->begin) =
                                                                    (*begin) ^ socket->mask[socket->mask_index];
                                                                ++begin;
                                                                socket->mask_index = (socket->mask_index + 1) % 4;
                                                            }
                                                            socket->mask_index = 4;
                                                            break;
                                                        case packet_type::text_final:
                                                        case packet_type::binary_final:
                                                            for (; socket->begin != socket->data.end();
                                                                 ++socket->begin) {
                                                                *(socket->begin) =
                                                                    (*begin) ^ socket->mask[socket->mask_index];
                                                                ++begin;
                                                                socket->mask_index = (socket->mask_index + 1) % 4;
                                                            }
                                                            {
                                                                message socket_message{
                                                                    {}, socket->type == packet_type::text_final};
                                                                socket_message.bytes.swap(socket->data);
                                                                _handle_message(
                                                                    static_cast<std::size_t>(socket->file_descriptor),
                                                                    socket_message);
                                                            }
                                                            socket->begin = socket->data.begin();
                                                            socket->mask_index = 4;
                                                            break;
                                                    }
                                                }
                                            } else {
                                                if (std::distance(begin, end) == 1) {
                                                    socket->buffer.assign(begin, end);
                                                    begin = end;
                                                } else {
                                                    if (((*std::next(begin)) >> 7) != 1) {
                                                        throw std::runtime_error("unmasked payload");
                                                    }
                                                    const auto final_packet = ((*begin) >> 7) == 1;
                                                    const auto opcode = static_cast<uint8_t>((*begin) & 0b1111);
                                                    std::size_t length = (*std::next(begin)) & 0b1111111;
                                                    if (length < 126) {
                                                        if (std::distance(begin, end) < 6) {
                                                            socket->buffer.assign(begin, end);
                                                            break;
                                                        }
                                                        std::advance(begin, 2);
                                                    } else if (length == 126) {
                                                        if (std::distance(begin, end) < 8) {
                                                            socket->buffer.assign(begin, end);
                                                            break;
                                                        }
                                                        std::advance(begin, 2);
                                                        length = (static_cast<uint16_t>(*begin) << 8);
                                                        ++begin;
                                                        length |= *begin;
                                                        ++begin;
                                                    } else {
                                                        if (std::distance(begin, end) < 14) {
                                                            socket->buffer.assign(begin, end);
                                                            break;
                                                        }
                                                        std::advance(begin, 2);
                                                        length = (static_cast<uint64_t>(*begin) << 56);
                                                        ++begin;
                                                        length |= (static_cast<uint64_t>(*begin) << 48);
                                                        ++begin;
                                                        length |= (static_cast<uint64_t>(*begin) << 40);
                                                        ++begin;
                                                        length |= (static_cast<uint64_t>(*begin) << 32);
                                                        ++begin;
                                                        length |= (static_cast<uint64_t>(*begin) << 24);
                                                        ++begin;
                                                        length |= (static_cast<uint64_t>(*begin) << 16);
                                                        ++begin;
                                                        length |= (static_cast<uint64_t>(*begin) << 8);
                                                        ++begin;
                                                        length |= *begin;
                                                        ++begin;
                                                    }
                                                    switch (opcode) {
                                                        case 0:
                                                            switch (socket->type) {
                                                                case packet_type::invalid:
                                                                case packet_type::text_final:
                                                                case packet_type::binary_final:
                                                                case packet_type::ping:
                                                                    socket->data.resize(length);
                                                                    socket->begin = socket->data.begin();
                                                                    socket->type = packet_type::invalid;
                                                                    break;
                                                                case packet_type::text:
                                                                case packet_type::binary: {
                                                                    const auto size = socket->data.size();
                                                                    socket->data.resize(size + length);
                                                                    socket->begin =
                                                                        std::next(socket->data.begin(), size);
                                                                    if (final_packet) {
                                                                        socket->type =
                                                                            (socket->type == packet_type::text ?
                                                                                 packet_type::text_final :
                                                                                 packet_type::binary_final);
                                                                    }
                                                                    break;
                                                                }
                                                            }
                                                            break;
                                                        case 1:
                                                            socket->data.resize(length);
                                                            socket->begin = socket->data.begin();
                                                            socket->type = final_packet ? packet_type::text_final :
                                                                                          packet_type::text;
                                                            break;
                                                        case 2:
                                                            socket->data.resize(length);
                                                            socket->begin = socket->data.begin();
                                                            socket->type = final_packet ? packet_type::binary_final :
                                                                                          packet_type::binary;
                                                            break;
                                                        case 9:
                                                            socket->data.resize(length);
                                                            socket->begin = socket->data.begin();
                                                            socket->type =
                                                                length < 126 ? packet_type::ping : packet_type::invalid;
                                                            break;
                                                        case 10:
                                                            socket->data.resize(length);
                                                            socket->begin = socket->data.begin();
                                                            socket->type = packet_type::invalid;
                                                            break;
                                                        default:
                                                            throw std::runtime_error("unknown opcode");
                                                    }
                                                    std::get<0>(socket->mask) = *begin;
                                                    ++begin;
                                                    std::get<1>(socket->mask) = *begin;
                                                    ++begin;
                                                    std::get<2>(socket->mask) = *begin;
                                                    ++begin;
                                                    std::get<3>(socket->mask) = *begin;
                                                    ++begin;
                                                    socket->mask_index = 0;
                                                }
                                            }
                                        }
                                        ++socket;
                                    } catch (const std::runtime_error&) {
                                        socket = erase(socket);
                                    }
                                    buffer.resize(1 << 12);
                                } else {
                                    try {
                                        auto header = parse_http_header(buffer.begin(), buffer.end());
                                        if (header.method != "GET" || header.protocol != "HTTP/1.1") {
                                            throw std::runtime_error("bad header");
                                        }
                                        auto upgrade_found = false;
                                        auto connection_found = false;
                                        std::string key;
                                        auto version_found = false;
                                        for (const auto& field : header.fields) {
                                            if (field.first == "Upgrade") {
                                                if (upgrade_found) {
                                                    throw std::runtime_error("bad header");
                                                }
                                                upgrade_found = true;
                                                if (field.second != "websocket") {
                                                    throw std::runtime_error("bad header");
                                                }
                                            } else if (field.first == "Connection") {
                                                if (connection_found) {
                                                    throw std::runtime_error("bad header");
                                                }
                                                connection_found = true;
                                                if (field.second != "Upgrade") {
                                                    throw std::runtime_error("bad header");
                                                }
                                            } else if (field.first == "Sec-WebSocket-Key") {
                                                if (!key.empty()) {
                                                    throw std::runtime_error("bad header");
                                                }
                                                key = field.second;
                                            } else if (field.first == "Sec-WebSocket-Version") {
                                                if (version_found) {
                                                    throw std::runtime_error("bad header");
                                                }
                                                version_found = true;
                                                if (field.second != "13") {
                                                    throw std::runtime_error("bad header");
                                                }
                                            }
                                        }
                                        if (!upgrade_found || !connection_found || key.empty() || !version_found) {
                                            throw std::runtime_error("bad header");
                                        }
                                        key += "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
                                        std::vector<uint8_t> hashed_key(20);
                                        sha1(key.begin(), key.end(), hashed_key.begin());
                                        {
                                            const auto content =
                                                std::string(
                                                    "HTTP/1.1 101 Switching Protocols\r\nUpgrade: "
                                                    "websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ")
                                                + bytes_to_encoded_characters(hashed_key) + "\r\n\r\n";
                                            const std::vector<uint8_t> payload(content.begin(), content.end());
                                            write(*socket, payload);
                                        }
                                        {
                                            const auto response = _handle_connection(
                                                static_cast<std::size_t>(socket->file_descriptor), header.url);
                                            if (!response.bytes.empty()) {
                                                auto payload = message_to_payload(response);
                                                write(*socket, payload);
                                            }
                                        }
                                        while (_accessing_sockets.test_and_set(std::memory_order_acquire)) {
                                        }
                                        socket->ready = true;
                                        _accessing_sockets.clear(std::memory_order_release);
                                        ++socket;
                                    } catch (const std::runtime_error&) {
                                        {
                                            const std::string content("HTTP/1.1 400 Bad Request\r\n\r\n");
                                            const std::vector<uint8_t> payload(content.begin(), content.end());
                                            write(*socket, payload);
                                        }
                                        socket = erase(socket);
                                    }
                                }
                            }
                        } else {
                            ++socket;
                        }
                    }
                    if (FD_ISSET(_socket_file_descriptor, &sockets_file_descriptor_set)) {
                        socket_file_descriptor_t socket_file_descriptor;
                        {
                            sockaddr_in address;
                            socklen_t size = sizeof(address);
                            socket_file_descriptor =
                                accept(_socket_file_descriptor, reinterpret_cast<sockaddr*>(&address), &size);
                        }
                        try {
                            check_socket(socket_file_descriptor);
                        } catch (const std::logic_error&) {
                        }
                        while (_accessing_sockets.test_and_set(std::memory_order_acquire)) {
                        }
                        _sockets.push_back(websocket{socket_file_descriptor});
                        _accessing_sockets.clear(std::memory_order_release);
                    }
                }
            });
        }
        specialized_server(const specialized_server&) = delete;
        specialized_server(specialized_server&&) = default;
        specialized_server& operator=(const specialized_server&) = delete;
        specialized_server& operator=(specialized_server&&) = default;
        virtual ~specialized_server() {
            _running.store(false, std::memory_order_release);
            _loop.join();
            for (const auto& socket : _sockets) {
                close_socket(socket.file_descriptor);
            }
#ifdef _WIN32
            WSACleanup();
#endif
        }
        virtual void broadcast(const message& socket_message) override {
            auto payload = message_to_payload(socket_message);
            while (_accessing_sockets.test_and_set(std::memory_order_acquire)) {
            }
            for (const auto& socket : _sockets) {
                if (socket.ready) {
                    write(socket, payload);
                }
            }
            _accessing_sockets.clear(std::memory_order_release);
        }
        virtual void send(std::size_t id, const message& socket_message) override {
            auto payload = message_to_payload(socket_message);
            while (_accessing_sockets.test_and_set(std::memory_order_acquire)) {
            }
            auto socket = std::find_if(_sockets.begin(), _sockets.end(), [=](const websocket& socket) {
                return socket.file_descriptor == id;
            });
            if (socket != _sockets.end() && socket->ready) {
                write(*socket, payload);
            }
            _accessing_sockets.clear(std::memory_order_release);
        }
        virtual void close(std::size_t id) override {
            while (_accessing_closing.test_and_set(std::memory_order_acquire)) {
            }
            while (_accessing_sockets.test_and_set(std::memory_order_acquire)) {
            }
            auto socket = std::find_if(_sockets.begin(), _sockets.end(), [=](const websocket& socket) {
                return socket.file_descriptor == id;
            });
            if (socket != _sockets.end()) {
                socket->closing = true;
            }
            _accessing_sockets.clear(std::memory_order_release);
            _accessing_closing.clear(std::memory_order_release);
        }

        protected:
        /// http_header contains the parameters of a HTTP header.
        struct http_header {
            std::string method;
            std::string url;
            std::string protocol;
            std::vector<std::pair<std::string, std::string>> fields;
        };

        /// packet_type specifies a socket packet status.
        enum class packet_type {
            invalid,
            text,
            binary,
            text_final,
            binary_final,
            ping,
        };

        /// websocket stores the parameters and data associated with a socket.
        struct websocket {
            socket_file_descriptor_t file_descriptor;
            bool ready;
            std::vector<uint8_t> data;
            std::vector<uint8_t>::iterator begin;
            std::array<uint8_t, 4> mask;
            uint8_t mask_index;
            std::vector<uint8_t> buffer;
            packet_type type;
            bool closing;
        };

        /// check throws if the function returns an error code.
        static void check(int32_t error, const std::string& message) {
#ifdef _WIN32
            if (error == SOCKET_ERROR) {
#else
            if (error < 0) {
#endif
                throw std::logic_error(message + " failed");
            }
        }

        /// check_socket throws if the socket is not valid, and returns the file descriptor otherwise.
        static socket_file_descriptor_t check_socket(socket_file_descriptor_t socket_file_descriptor) {
#ifdef _WIN32
            if (socket_file_descriptor == INVALID_SCOKET) {
#else
            if (socket_file_descriptor < 0) {
#endif
                throw std::logic_error("the socket is not valid");
            }
            return socket_file_descriptor;
        }

        /// close_socket terminates the connection with a client.
        static void close_socket(socket_file_descriptor_t socket_file_descriptor) {
#ifdef _WIN32
            if (shutdown(socket_file_descriptor, SD_BOTH) == 0) {
                ::closesocket(socket_file_descriptor);
            }
#else
            if (shutdown(socket_file_descriptor, SHUT_RDWR) == 0) {
                ::close(socket_file_descriptor);
            }
#endif
        }

        /// consume reads from a range while the first condition is true.
        template <typename Iterator, typename IsValid, typename IsEnd>
        static std::string consume(Iterator& begin, Iterator end, IsValid is_valid, IsEnd is_end) {
            std::string result;
            for (; begin != end; ++begin) {
                if (is_end(*begin)) {
                    if (result.empty()) {
                        throw std::runtime_error("unexpected character");
                    }
                    ++begin;
                    return result;
                } else if (is_valid(*begin)) {
                    result += *begin;
                } else {
                    throw std::runtime_error("unexpected character");
                }
            }
            throw std::runtime_error("unexpected end of range");
        }

        /// consume reads a single character, and throws if the condition is not true.
        template <typename Iterator, typename IsValid>
        static void consume(Iterator& begin, Iterator end, IsValid is_valid) {
            if (begin == end) {
                throw std::runtime_error("unexpected end of range");
            }
            if (!is_valid(*begin)) {
                throw std::runtime_error("unexpected character");
            }
            ++begin;
        }

        /// parse_http_header parses a HTTP header.
        template <typename Iterator>
        static http_header parse_http_header(Iterator begin, Iterator end) {
            auto isupper = [](int ch) { return std::isupper(ch); };
            auto isgraph = [](int ch) { return std::isgraph(ch); };
            auto isprint = [](int ch) { return std::isprint(ch); };
            auto isspace = [](int ch) { return ch == ' '; };
            auto isreturn = [](int ch) { return ch == '\r'; };
            auto isbreak = [](int ch) { return ch == '\n'; };
            auto iscolon = [](int ch) { return ch == ':'; };
            http_header header;
            header.method = consume(begin, end, isupper, isspace);
            header.url = consume(begin, end, isgraph, isspace);
            header.protocol = consume(begin, end, isgraph, isreturn);
            consume(begin, end, isbreak);
            for (;;) {
                if (begin == end) {
                    throw std::runtime_error("unexpected end of range");
                }
                if (isreturn(*begin)) {
                    ++begin;
                    consume(begin, end, isbreak);
                    break;
                }
                header.fields.emplace_back();
                header.fields.back().first = consume(begin, end, isgraph, iscolon);
                consume(begin, end, isspace);
                header.fields.back().second = consume(begin, end, isprint, isreturn);
                consume(begin, end, isbreak);
            }
            return header;
        }

        /// bytes_to_encoded_characters converts bytes to a URL-encoded string.
        /// It is equivalent to JavaScript's btoa function.
        static std::string bytes_to_encoded_characters(const std::vector<uint8_t>& bytes) {
            std::string output;
            output.reserve(bytes.size() * 4);
            const std::string characters("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");
            std::size_t data = 0;
            auto length = bytes.size();
            for (; length > 2; length -= 3) {
                data =
                    ((static_cast<std::size_t>(bytes[bytes.size() - length]) << 16)
                     | (static_cast<std::size_t>(bytes[bytes.size() - length + 1]) << 8)
                     | bytes[bytes.size() - length + 2]);
                output.push_back(characters[(data & (63 << 18)) >> 18]);
                output.push_back(characters[(data & (63 << 12)) >> 12]);
                output.push_back(characters[(data & (63 << 6)) >> 6]);
                output.push_back(characters[data & 63]);
            }
            if (length == 2) {
                data = (static_cast<std::size_t>(bytes[bytes.size() - length]) << 16)
                       | (static_cast<std::size_t>(bytes[bytes.size() - length + 1]) << 8);
                output.push_back(characters[(data & (63 << 18)) >> 18]);
                output.push_back(characters[(data & (63 << 12)) >> 12]);
                output.push_back(characters[(data & (63 << 6)) >> 6]);
                output.push_back('=');
            } else if (length == 1) {
                data = (static_cast<std::size_t>(bytes[bytes.size() - length]) << 16);
                output.push_back(characters[(data & (63 << 18)) >> 18]);
                output.push_back(characters[(data & (63 << 12)) >> 12]);
                output.push_back('=');
                output.push_back('=');
            }
            return output;
        }

        /// message_to_payload generates a websocket header for the given message.
        static std::vector<uint8_t> message_to_payload(const message& socket_message) {
            std::vector<uint8_t> output{static_cast<uint8_t>(0b10000000 | (socket_message.is_string ? 1 : 2)), 0};
            if (socket_message.bytes.size() < 126) {
                output[1] = static_cast<uint8_t>(socket_message.bytes.size());
                output.resize(socket_message.bytes.size() + 2);
                std::copy(socket_message.bytes.begin(), socket_message.bytes.end(), std::next(output.begin(), 2));
            } else if (socket_message.bytes.size() < (1 << 16)) {
                output[1] = static_cast<uint8_t>(126);
                output.resize(socket_message.bytes.size() + 4);
                output[2] = static_cast<uint8_t>((socket_message.bytes.size() >> 8) & 0xff);
                output[3] = static_cast<uint8_t>(socket_message.bytes.size() & 0xff);
                std::copy(socket_message.bytes.begin(), socket_message.bytes.end(), std::next(output.begin(), 4));
            } else {
                output[1] = static_cast<uint8_t>(127);
                output.resize(socket_message.bytes.size() + 10);
                output[2] = static_cast<uint8_t>((socket_message.bytes.size() >> 56) & 0xff);
                output[3] = static_cast<uint8_t>((socket_message.bytes.size() >> 48) & 0xff);
                output[4] = static_cast<uint8_t>((socket_message.bytes.size() >> 40) & 0xff);
                output[5] = static_cast<uint8_t>((socket_message.bytes.size() >> 32) & 0xff);
                output[6] = static_cast<uint8_t>((socket_message.bytes.size() >> 24) & 0xff);
                output[7] = static_cast<uint8_t>((socket_message.bytes.size() >> 16) & 0xff);
                output[8] = static_cast<uint8_t>((socket_message.bytes.size() >> 8) & 0xff);
                output[9] = static_cast<uint8_t>(socket_message.bytes.size() & 0xff);
                std::copy(socket_message.bytes.begin(), socket_message.bytes.end(), std::next(output.begin(), 10));
            }
            return output;
        }

        /// write sends a message to a socket.
        virtual void write(const websocket& socket, const std::vector<uint8_t>& payload) {
            ::send(socket.file_descriptor, payload.data(), payload.size(), 0);
        }

        /// erase terminates a client connexion and removes the listed socket.
        virtual typename std::vector<websocket>::iterator erase(typename std::vector<websocket>::iterator socket) {
            const auto socket_file_descriptor = socket->file_descriptor;
            const auto ready = socket->ready;
            while (_accessing_sockets.test_and_set(std::memory_order_acquire)) {
            }
            socket = _sockets.erase(socket);
            _accessing_sockets.clear(std::memory_order_release);
            close_socket(socket_file_descriptor);
            if (ready) {
                _handle_disconnection(static_cast<std::size_t>(socket_file_descriptor));
            }
            return socket;
        }

        HandleConnection _handle_connection;
        HandleMessage _handle_message;
        HandleDisconnection _handle_disconnection;
        socket_file_descriptor_t _socket_file_descriptor;
        std::atomic_flag _accessing_sockets;
        std::atomic_flag _accessing_closing;
        std::vector<websocket> _sockets;
        std::atomic_bool _running;
        std::thread _loop;
    };

    /// make_server creates a server from functors.
    template <typename HandleConnection, typename HandleMessage, typename HandleDisconnection>
    std::unique_ptr<specialized_server<HandleConnection, HandleMessage, HandleDisconnection>> make_server(
        uint16_t port,
        HandleConnection handle_connection,
        HandleMessage handle_message,
        HandleDisconnection handle_disconnection) {
        return std::unique_ptr<specialized_server<HandleConnection, HandleMessage, HandleDisconnection>>(
            new specialized_server<HandleConnection, HandleMessage, HandleDisconnection>(
                port,
                std::forward<HandleConnection>(handle_connection),
                std::forward<HandleMessage>(handle_message),
                std::forward<HandleDisconnection>(handle_disconnection)));
    }
}
