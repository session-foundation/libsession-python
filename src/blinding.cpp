#include "blinding.hpp"

#include <pybind11/cast.h>

#include <session/blinding.hpp>

#include "common.hpp"

namespace session {

void pybind_blinding(py::module m) {
    using namespace py::literals;
    m.def(
            "blind25_id",
            [](py::str session_id, py::str server_pk) {
                return blind25_id(
                        static_cast<std::string>(session_id), static_cast<std::string>(server_pk));
            },
            "session_id"_a,
            "server_pk"_a,
            "Computed a blinded session id using 25xxx-style Community pubkey blinding.\n\n"
            "Takes the (unblinded) Session ID and server pubkey as hex strings; returns the "
            "blinded id as a hex string.  This blinded pubkey is an Ed25519 pubkey, prefixed with "
            "'25'.");

    m.def(
            "blind25_id",
            [](py::bytes session_id, py::bytes server_pk) {
                auto blinded = blind25_id(
                        usv_from_pybytes(session_id, "session_id", 33, 32),
                        usv_from_pybytes(server_pk, "server_pk", 32));
                return py::bytes{from_unsigned(blinded.data()), blinded.size()};
            },
            "session_id"_a,
            "server_pk"_a,
            "Computed a blinded session id using 25xxx-style Community pubkey blinding.\n\n"
            "Takes the (unblinded) Session ID and server pubkey as bytes strings; the session ID "
            "may omit the 05 prefix; returns the blinded id as a length-33 bytes.  This blinded "
            "pubkey is an Ed25519 pubkey, prefixed with 0x25.");

    struct PyKeypair {
        py::bytes pubkey;
        py::bytes privkey;

        PyKeypair(const std::pair<session::uc32, session::cleared_uc32>& k)
            : pubkey{reinterpret_cast<const char*>(k.first.data()), k.first.size()},
              privkey{reinterpret_cast<const char*>(k.second.data()), k.second.size()} {}
    };

    py::class_<PyKeypair>(m, "Keypair")
        .def_readonly("pubkey", &PyKeypair::pubkey)
        .def_readonly("privkey", &PyKeypair::privkey);

    m.def(
            "blind15_key_pair",
            [](py::bytes ed_sk_bytes, py::bytes server_pk) {
                return std::make_unique<PyKeypair>(blind15_key_pair(
                        usv_from_pybytes(ed_sk_bytes, "ed25519_seckey", 32, 64),
                        usv_from_pybytes(server_pk, "server_pk", 32, 64)));
            },
            "ed25519_seckey"_a,
            "server_pubkey"_a,
            "Computed a blinded session id key pair using 15xxx-style Community pubkey "
            "blinding.\n\n"
            "Takes the (unblinded) Session ID ed seed and server pubkey as bytes strings; Returns "
            "blinded Ed25519 seckey and pubkey.");


    m.def(
            "blind25_key_pair",
            [](py::bytes ed_sk_bytes, py::bytes server_pk) {
                return std::make_unique<PyKeypair>(blind25_key_pair(
                        usv_from_pybytes(ed_sk_bytes, "ed25519_seckey", 32, 64),
                        usv_from_pybytes(server_pk, "server_pk", 32, 64)));
            },
            "ed25519_seckey"_a,
            "server_pubkey"_a,
            "Computed a blinded session id key pair using 25xxx-style Community pubkey "
            "blinding.\n\n"
            "Takes the (unblinded) Session ID ed seed and server pubkey as bytes strings; Returns "
            "blinded Ed25519 seckey and pubkey.");


    m.def(
            "blind15_sign",
            [](py::bytes ed_sk_bytes, std::string_view server_pk, py::bytes message) {
                auto ed_sk = usv_from_pybytes(ed_sk_bytes, "ed25519_seckey", 32, 64);
                auto sig = blind15_sign(ed_sk, server_pk, usv_from_pybytes(message));
                return py::bytes{from_unsigned(sig.data()), sig.size()};
            },
            "ed25519_seckey"_a,
            "server_pubkey"_a,
            "message"_a,

            "Signs a message that is verifiable using the blinded 15xxx pubkey version of the "
            "given Session ID.\n\n"
            "- ed25519_seckey is the sodium-style 64-byte Ed25519 secret key underlying the "
            "Session ID, or *just* the 32-byte seed (in which case the pubkey will be computed).\n"
            "- server_pubkey is the community server pubkey, as a `str` (64 hex digits) or `bytes` "
            "(32)\n"
            "- message is the message to sign, in bytes\n\n"
            "Returns the 64-byte signature as bytes\n\n"
            "Note that there is no associated `blind15_verify` function because the resulting "
            "signature is verifiable as a standard Ed25519 signature using the blinded pubkey.");

    m.def(
            "blind25_sign",
            [](py::bytes ed_sk_bytes, std::string_view server_pk, py::bytes message) {
                auto ed_sk = usv_from_pybytes(ed_sk_bytes, "ed25519_seckey", 32, 64);
                auto sig = blind25_sign(ed_sk, server_pk, usv_from_pybytes(message));
                return py::bytes{from_unsigned(sig.data()), sig.size()};
            },
            "ed25519_seckey"_a,
            "server_pubkey"_a,
            "message"_a,

            "Signs a message that is verifiable using the blinded 25xxx pubkey version of the "
            "given Session ID.\n\n"
            "- ed25519_seckey is the sodium-style 64-byte Ed25519 secret key underlying the "
            "Session ID, or *just* the 32-byte seed (in which case the pubkey will be computed).\n"
            "- server_pubkey is the community server pubkey, as a `str` (64 hex digits) or `bytes` "
            "(32)\n"
            "- message is the message to sign, in bytes\n\n"
            "Returns the 64-byte signature as bytes\n\n"
            "Note that there is no associated `blind25_verify` function because the resulting "
            "signature is verifiable as a standard Ed25519 signature using the blinded pubkey.");
}

}  // namespace session
