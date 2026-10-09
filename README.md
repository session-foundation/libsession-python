# libsession-python

Python interface around (some of) [libsession-util](https://github.com/oxen-io/libsession-util).

This library is available pre-compiled for recent Debian/Ubuntu distributions via the [Oxen apt
repository](https://deb.oxen.io).

## Building from source

Dependencies:

- python3-pip
- python3-dev
- pybind11-dev
- libsession-util-dev

Check the source out with

    $ git clone https://github.com/oxen-io/libsession-python
    $ cd libsession-python

Install using:

    $ pip3 install .

## Tests

    $ pip3 install pytest
    $ pytest

The tests import the installed module, so run `pip3 install .` first.
