#!/bin/sh
find -name '*.c' -or -name '*.h' | xargs clang-format -i 