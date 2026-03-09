#!/bin/bash

echo " Secure Crypto Middleware Build "

echo ""
echo "Building Test Runner..."

g++ -std=c++20 -Wall -Wextra -O2 \
-Iinclude \
src/util/*.cpp \
src/context/*.cpp \
src/keys/*.cpp \
src/crypto/*.cpp \
src/api/*.cpp \
tests/basic_flow_test.cpp \
-o test_runner

if [ $? -ne 0 ]; then
    echo "Test build failed."
    exit 1
fi

echo ""
echo "Running Tests..."
./test_runner


echo ""
echo "Building Demo Application..."

g++ -std=c++20 -Wall -Wextra -O2 \
-Iinclude \
src/util/*.cpp \
src/context/*.cpp \
src/keys/*.cpp \
src/crypto/*.cpp \
src/api/*.cpp \
demo/demo.cpp \
-o demo_app

if [ $? -ne 0 ]; then
    echo "Demo build failed."
    exit 1
fi

echo ""
echo "Running Demo..."
./demo_app
