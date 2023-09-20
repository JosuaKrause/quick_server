#!/usr/bin/env bash

set -ex

cd -- "$( dirname -- "${BASH_SOURCE[0]:-$0}" )/../" &> /dev/null

find . -type d \( \
        -path './dist' -o \
        -path './build' -o \
        -path './.*' \
        \) -prune -o \( \
        -name '*.py' -o \
        -name '*.pyi' \
        \) \
    | grep -vF './dist' \
    | grep -vF './build' \
    | grep -vF './.'
