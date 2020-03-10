#!/bin/sh

find libpirate demos -name *.h -o -name *.c -o -name *.cpp -o -name *.hpp | \
    xargs clang-format -style=file -i -fallback-style=none

git diff > clang_format.patch

if [ ! -s clang_format.patch ]
then
    rm clang_format.patch
    exit 0
fi

echo "Check clang_format.patch for format errors"
exit 1
