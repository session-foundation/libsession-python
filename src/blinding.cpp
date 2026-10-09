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
                        bytes_from_pybytes(session_id, "session_id", 33, 32),
                        bytes_from_pybytes(server_pk, "server_pk", 32));
                return py::bytes{to_string_view(blinded)};
            },
            "session_id"_a,
            "server_pk"_a,
            "Computed a blinded session id using 25xxx-style Community pubkey blinding.\n\n"
            "Takes the (unblinded) Session ID and server pubkey as bytes strings; the session ID "
            "may omit the 05 prefix; returns the blinded id as a length-33 bytes.  This blinded "
            "pubkey is an Ed25519 pubkey, prefixed with 0x25.");

    m.def(
            "blind15_id",
            [](py::str session_id, py::str server_pk) {
                auto ids = blind15_id(
                        static_cast<std::string>(session_id), static_cast<std::string>(server_pk));
                return py::make_tuple(ids[0], ids[1]);
            },
            "session_id"_a,
            "server_pk"_a,
            "Computes the two possible blinded session ids using 15xxx-style Community pubkey "
            "blinding.\n\n"
            "Takes the (unblinded) Session ID and server pubkey as hex strings; returns both "
            "blinded ids as a 2-tuple of hex strings, each an Ed25519 pubkey prefixed with '15'.  "
            "The positive one is first.\n\n"
            "Both are returned because blinding an X25519 Session ID recovers the underlying "
            "Ed25519 pubkey only up to its sign, so which of the two an account exists under is "
            "not derivable from the Session ID alone.  Use `blind15_key_pair` instead when the "
            "Ed25519 secret key is known, which resolves the sign.");

    m.def(
            "blind15_id",
            [](py::bytes session_id, py::bytes server_pk) {
                auto blinded = blind15_id(
                        bytes_from_pybytes(session_id, "session_id", 33, 32),
                        bytes_from_pybytes(server_pk, "server_pk", 32));
                auto pos = py::bytes{to_string_view(blinded)};
                blinded[32] ^= 0x80;
                return py::make_tuple(std::move(pos), py::bytes{to_string_view(blinded)});
            },
            "session_id"_a,
            "server_pk"_a,
            "Computes the two possible blinded session ids using 15xxx-style Community pubkey "
            "blinding.\n\n"
            "Takes the (unblinded) Session ID and server pubkey as bytes strings; the session ID "
            "may omit the 05 prefix; returns both blinded ids as a 2-tuple of length-33 bytes, "
            "each an Ed25519 pubkey prefixed with 0x15.  The positive one is first.\n\n"
            "Both are returned, unlike the C++ overload of the same name, because which of the "
            "two an account exists under is decided by a sign this derivation cannot recover, and "
            "picking the wrong one does not announce itself: a SOGS server will create the "
            "account row for an id nobody holds.  Use `blind15_key_pair` instead when the Ed25519 "
            "secret key is known.");

    struct PyKeypair {
        py::bytes pubkey;
        py::bytes privkey;

        PyKeypair(const std::pair<session::uc32, session::cleared_uc32>& k)
            : pubkey{to_string_view(k.first)}, privkey{to_string_view(k.second)} {}
    };

    py::class_<PyKeypair>(m, "Keypair")
        .def_readonly("pubkey", &PyKeypair::pubkey)
        .def_readonly("privkey", &PyKeypair::privkey);

    m.def(
            "blind15_key_pair",
            [](py::bytes ed_sk_bytes, py::bytes server_pk) {
                return std::make_unique<PyKeypair>(blind15_key_pair(
                        bytes_from_pybytes(ed_sk_bytes, "ed25519_seckey", 32, 64),
                        bytes_from_pybytes(server_pk, "server_pk", 32, 64)));
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
                        bytes_from_pybytes(ed_sk_bytes, "ed25519_seckey", 32, 64),
                        bytes_from_pybytes(server_pk, "server_pk", 32, 64)));
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
                auto ed_sk = bytes_from_pybytes(ed_sk_bytes, "ed25519_seckey", 32, 64);
                auto sig = blind15_sign(ed_sk, server_pk, bytes_from_pybytes(message));
                return py::bytes{to_string_view(sig)};
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
                auto ed_sk = bytes_from_pybytes(ed_sk_bytes, "ed25519_seckey", 32, 64);
                auto sig = blind25_sign(ed_sk, server_pk, bytes_from_pybytes(message));
                return py::bytes{to_string_view(sig)};
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
