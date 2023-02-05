#!/usr/bin/python3

# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
""" Harnass for fuzzing https://github.com/un33k/python-slugify """

import sys
import struct
import atheris
from slugify import slugify

def test_slugify(inp):
    """ Testing slugify with default settings """
    slugify(inp)

def test_slugify_entities(inp):
    """ Testing slugify with entities=False """
    slugify(inp, entities=False)

def test_slugify_decimal(inp):
    """ Testing slugify with decimal=False """
    slugify(inp, decimal=False)

def test_slugify_hexadecimal(inp):
    """ Testing slugify with hexadecimal=False """
    slugify(inp, hexadecimal=False)

def test_slugify_word_boundary(inp):
    """ Testing slugify with word_boundary=True """
    slugify(inp, word_boundary=True)

def test_slugify_save_order(inp):
    """ Testing slugify with save_order=True """
    slugify(inp, save_order=True)

def test_slugify_stopwords(inp):
    """ Testing slugify with  stopwords=['the'] """
    slugify(inp, stopwords=['the'])

def test_slugify_lowercase(inp):
    """ Testing slugify with lowercase=False """
    slugify(inp, lowercase=False)

def test_slugify_allow_unicode(inp):
    """ Testing slugify with allow_unicode=True """
    slugify(inp, allow_unicode=True)

LONGSTR = 1
MEDIUMSTR = 2
SHORTSTR = 3
SSHORTSTR = 4

TESTS = [
    (test_slugify, str),
    (test_slugify_entities, str),
    (test_slugify_decimal, str),
    (test_slugify_hexadecimal, str),
    (test_slugify_word_boundary, str),
    (test_slugify_save_order, str),
    (test_slugify_stopwords, str),
    (test_slugify_lowercase, str),
    (test_slugify_allow_unicode, str),
]

def get_input(input_bytes, idx):
    """ Get input of the right type/size """
    fdp = atheris.FuzzedDataProvider(input_bytes)
    if TESTS[idx][1] == str:
        return fdp.ConsumeUnicode(sys.maxsize)
    if TESTS[idx][1] == LONGSTR:
        return fdp.ConsumeUnicode(100000)
    if TESTS[idx][1] == MEDIUMSTR:
        return fdp.ConsumeUnicode(10000)
    if TESTS[idx][1] == SHORTSTR:
        return fdp.ConsumeUnicode(1000)
    if TESTS[idx][1] == SSHORTSTR:
        return fdp.ConsumeUnicode(100)
    return None

def test_one_input(input_bytes):
    """ Fuzzer's entry point """
    if len(input_bytes) < 1:
        return
    idx = struct.unpack('>B', input_bytes[:1])[0]
    if idx >= len(TESTS):
        return
    TESTS[idx][0](get_input(input_bytes[1:], idx))

def main():
    """ main function """
    atheris.Setup(sys.argv, test_one_input, enable_python_coverage=False)
    atheris.Fuzz()


if __name__ == "__main__":
    atheris.instrument_all()
    main()
