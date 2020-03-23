#!/usr/bin/env bash

# Install Go
echo "Installing ${GO_VERSION} with gimme."
eval "$(curl -sL https://raw.githubusercontent.com/travis-ci/gimme/master/gimme | GIMME_GO_VERSION=${GO_VERSION} bash)"

# To transform the test output to junit and be reported in the CI Jenkins
go get -v -u github.com/jstemmer/go-junit-report
mkdir -p build

export OUT_FILE='build/test-report.out'
go test ./... | tee ${OUT_FILE}
go-junit-report < "${OUT_FILE}" > build/junit-report.xml
