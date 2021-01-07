#!/usr/bin/env bash

# Install Go
echo "Installing ${GO_VERSION} with gimme."
eval "$(curl -sL https://raw.githubusercontent.com/travis-ci/gimme/master/gimme | GIMME_GO_VERSION=${GO_VERSION} bash)"

echo "Run the tests"
mkdir -p build
go get -v -u gotest.tools/gotestsum
gotestsum --junitfile build/junit-report.xml -- -v ./...
