#include "onionreq.hpp"

#include <pybind11/cast.h>

#include <session/onionreq/parser.hpp>

#include "common.hpp"

namespace session::onionreq {

namespace {

    // Wrapper so that we can hold the payload as bytes, clearing the original, rather than needing
    // to hold it and make a second copy every time it is accessed.
    class PyOnionReqParser : public OnionReqParser {
      public:
        using OnionReqParser::OnionReqParser;

        py::bytes payload_b;
    };

}  // namespace

void pybind(pybind11::module m) {
    using namespace pybind11::literals;
    py::class_<PyOnionReqParser>(
            m,
            "OnionReqParser",
            "Class holding a parsed reply that is able to encrypt a reply to the message sender")

            .def(py::init([](py::bytes pubkey_b,
                             py::bytes privkey_b,
                             py::bytes request_b,
                             size_t max_size) {
                     auto pubkey = span_u8_from_pybytes(pubkey_b, "x25519_pubkey", 32);
                     auto privkey = span_u8_from_pybytes(privkey_b, "x25519_privkey", 32);
                     auto request = span_u8_from_pybytes(request_b);
                     PyOnionReqParser parser{pubkey, privkey, request, max_size};
                     std::vector<uint8_t> pl = parser.move_payload();
                     parser.payload_b =
                             py::bytes{reinterpret_cast<const char*>(pl.data()), pl.size()};
                     return parser;
                 }),
                 "x25519_pubkey"_a,
                 "x25519_privkey"_a,
                 "request"_a,
                 "max_size"_a = DEFAULT_MAX_SIZE,
                 "Parses and decrypts an incoming onion request meant for the given curve25519 "
                 "pubkey/privkey.  Raises on parse or decryption failure.")

            .def_readonly(
                    "payload",
                    &PyOnionReqParser::payload_b,
                    "Accesses the decrypted payload of the request.")

            .def_property_readonly(
                    "remote_pubkey",
                    [](const PyOnionReqParser& parser) {
                        auto p = parser.remote_pubkey();
                        return py::bytes{reinterpret_cast<const char*>(p.data()), p.size()};
                    },
                    "Returns the remote_pubkey of the request.")

            .def(
                    "encrypt_reply",
                    [](const PyOnionReqParser& parser, py::bytes reply) {
                    std::vector<uint8_t> encr = parser.encrypt_reply(span_u8_from_pybytes(reply));
                        return py::bytes{reinterpret_cast<const char*>(encr.data()), encr.size()};
                    },
                    "reply"_a,
                    "Appropriately encrypts a reply to return to the sender");
}

}  // namespace session::onionreq
