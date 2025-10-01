#include <pybind11/pytypes.h>

#include <session/util.hpp>
#include <type_traits>
#include <string_view>
#include <span>
#include <cstdint>

namespace py = pybind11;

using namespace std::literals;
using namespace py::literals;

namespace session {

// Takes a py::bytes, returns a std::string_view pointing at its contents.
inline std::string_view sv_from_pybytes(const py::bytes& in) {
    char* ptr;
    ssize_t sz;
    PyBytes_AsStringAndSize(in.ptr(), &ptr, &sz);
    return std::string_view(ptr, static_cast<size_t>(sz));
}

inline std::span<const uint8_t> span_u8_from_pybytes(const py::bytes& in) {
    char* ptr;
    ssize_t sz;
    PyBytes_AsStringAndSize(in.ptr(), &ptr, &sz);
    auto result = std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(ptr), static_cast<size_t>(sz));
    return result;
}

// Takes a py::bytes, name, and 1+ size arguments: the bytes length must match one of the given
// sizes, or else an exception will be thrown (referencing the given name, e.g. argument name).
template <typename... Sizes, typename = std::enable_if_t<(std::is_integral_v<Sizes> && ...)>>
std::string_view sv_from_pybytes(
        const py::bytes& in, std::string_view name, size_t size0, Sizes... moresizes) {
    auto sv = sv_from_pybytes(in);
    if (((sv.size() != size0) && ... && (sv.size() != static_cast<size_t>(moresizes)))) {
        auto err = "invalid bytes size (" + std::to_string(sv.size()) + " for '" +
                   std::string{name} + "'. Expected one of: " + std::to_string(size0);
        ((void)(err += ", " + std::to_string(moresizes)), ...);
        throw std::invalid_argument{std::move(err)};
    }
    return sv;
}

template <typename... Sizes, typename = std::enable_if_t<(std::is_integral_v<Sizes> && ...)>>
std::span<const uint8_t> span_u8_from_pybytes(
        const py::bytes& in, std::string_view name, size_t size0, Sizes... moresizes) {
    auto sv = span_u8_from_pybytes(in);
    if (((sv.size() != size0) && ... && (sv.size() != static_cast<size_t>(moresizes)))) {
        auto err = "invalid bytes size (" + std::to_string(sv.size()) + " for '" +
                   std::string{name} + "'. Expected one of: " + std::to_string(size0);
        ((void)(err += ", " + std::to_string(moresizes)), ...);
        throw std::invalid_argument{std::move(err)};
    }
    return sv;
}

}  // namespace session
