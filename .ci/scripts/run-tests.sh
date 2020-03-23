#!/usr/bin/env bash

# Install Go
echo "Installing ${GO_VERSION} with gimme."
eval "$(curl -sL https://raw.githubusercontent.com/travis-ci/gimme/master/gimme | GIMME_GO_VERSION=${GO_VERSION} bash)"

echo "Run the tests"
mkdir -p build
export OUT_FILE='build/test-report.out'
go test -v ./... | tee ${OUT_FILE}

# To transform the test output to junit and be reported in the CI Jenkins
echo "Transform test report to JUnit"
go get -v -u github.com/jstemmer/go-junit-report
cat "${OUT_FILE}" | go-junit-report > build/junit-report.xml
