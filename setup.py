from setuptools import setup
from glob import glob

# Available at setup time due to pyproject.toml
from pybind11.setup_helpers import Pybind11Extension, build_ext

__version__ = "0.1.0"

ext_modules = [
    Pybind11Extension(
        "session_util",
        sorted(glob("src/*.cpp")),
        cxx_std=20,
        libraries=["session-config", "session-crypto", "session-network"],
    ),
]

setup(
    name="session-util",
    version=__version__,
    author="Jason Rhinelander",
    author_email="jason@session.foundation",
    url="https://github.com/session-foundation/libsession-python",
    description="Python wrapper for the libsession utilities library",
    long_description="",
    ext_modules=ext_modules,
    zip_safe=False,
    python_requires=">=3.7",
)
