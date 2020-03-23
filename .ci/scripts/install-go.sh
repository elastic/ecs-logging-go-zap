#!/usr/bin/env bash

GO_VERSION=${1:-1.12.7}

# Install Go
echo "Installing ${GO_VERSION} with gimme."
eval "$(curl -sL https://raw.githubusercontent.com/travis-ci/gimme/master/gimme | GIMME_GO_VERSION=${GO_VERSION} bash)"
