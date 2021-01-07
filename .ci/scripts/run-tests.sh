#!/usr/bin/env bash

echo "Run the tests"
mkdir -p build
go get -v -u gotest.tools/gotestsum
gotestsum --junitfile build/junit-report.xml -- -v ./...
