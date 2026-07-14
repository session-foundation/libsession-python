#include <pybind11/pytypes.h>

#include <session/util.hpp>
#include <type_traits>

namespace py = pybind11;

using namespace std::literals;
using namespace py::literals;

namespace session {

// Takes a py::bytes, returns a span of unsigned char pointing at its contents.
inline std::span<const unsigned char> bytes_from_pybytes(const py::bytes& in) {
    char* ptr;
    ssize_t sz;
    PyBytes_AsStringAndSize(in.ptr(), &ptr, &sz);
    return {reinterpret_cast<const unsigned char*>(ptr), static_cast<size_t>(sz)};
}

// Takes a py::bytes, name, and 1+ size arguments: the bytes length must match one of the given
// sizes, or else an exception will be thrown (referencing the given name, e.g. argument name).
template <typename... Sizes, typename = std::enable_if_t<(std::is_integral_v<Sizes> && ...)>>
std::span<const unsigned char> bytes_from_pybytes(
        const py::bytes& in, std::string_view name, size_t size0, Sizes... moresizes) {
    auto bytes = bytes_from_pybytes(in);
    if (((bytes.size() != size0) && ... && (bytes.size() != static_cast<size_t>(moresizes)))) {
        auto err = "invalid bytes size (" + std::to_string(bytes.size()) + " for '" +
                   std::string{name} + "'. Expected one of: " + std::to_string(size0);
        ((void)(err += ", " + std::to_string(moresizes)), ...);
        throw std::invalid_argument{std::move(err)};
    }
    return bytes;
}

}  // namespace session
