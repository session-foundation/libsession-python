#include "xed25519.hpp"

#include <session/xed25519.hpp>

#include "common.hpp"

namespace session::xed25519 {

void pybind(pybind11::module m) {
    using namespace pybind11::literals;

    m.def(
            "sign",
            [](py::bytes x25519_privkey, py::bytes msg) {
                auto a = sv_from_pybytes(x25519_privkey, "x25519_privkey", 32);
                auto sig = sign(a, sv_from_pybytes(msg));
                return py::bytes(reinterpret_cast<const char*>(sig.data()), sig.size());
            },
            "x25519_privkey"_a,
            "msg"_a,
            "Constructs an XEd25519 signature of `msg` using the given X25519 private key");

    m.def(
            "pubkey",
            [](py::bytes x25519_pubkey) {
                auto A = sv_from_pybytes(x25519_pubkey, "x25519_pubkey", 32);
                auto edpk = pubkey(A);
                return py::bytes(reinterpret_cast<const char*>(edpk.data()), edpk.size());
            },
            "x25519_pubkey"_a,
            "Returns the derived Ed25519 pubkey from a X25519 pubkey.  There are two possible "
            "Ed25519 pubkeys that convert to any given X25519 pubkey (via sodium's Ed -> curve "
            "conversion functions), which differ in their sign bit: this function always returns "
            "the positive (i.e. with the 0x80 bit of the last byte unset), as required by the "
            "XEd25519 specification.  (You can obtain the alternative, i.e. the negative, by "
            "setting the 0x80 bit in the last byte of the returned pubkey.)");

    m.def(
            "verify",
            [](py::bytes signature, py::bytes x25519_pubkey, py::bytes msg) {
                auto sig = sv_from_pybytes(signature, "signature", 64);
                auto A = sv_from_pybytes(x25519_pubkey, "x25519_pubkey", 32);
                return verify(sig, A, sv_from_pybytes(msg));
            },
            "signature"_a,
            "x25519_pubkey"_a,
            "msg"_a,
            "Verifies the XEd25519 signature `signature` of `msg` allegedly signed by "
            "`x25519_pubkey`.");
}

}  // namespace session::xed25519
