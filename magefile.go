// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

// +build mage

package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/magefile/mage/mg" // mg contains helpful utility functions, like Deps
)

var Default = Update

// Update go files to create ecs fields and contain license header
func Update() error {
	mg.Deps(InstallDeps)
	fmt.Println("Updating...")

	if err := updateECS(); err != nil {
		return err
	}
	for _, cmd := range []*exec.Cmd{
		exec.Command("go-licenser", "."),
		exec.Command("go", "fmt"),
		exec.Command("go", "mod", "tidy"),
	} {
		if err := cmd.Run(); err != nil {
			return err
		}
	}
	return nil
}

// Install development dependencies
func InstallDeps() error {
	fmt.Println("Installing Deps...")
	for _, cmd := range []*exec.Cmd{
		exec.Command("go", "get", "github.com/elastic/go-licenser"),
		exec.Command("go", "get", "github.com/urso/go-ecsfieldgen"),
	} {
		if err := cmd.Run(); err != nil {
			return err
		}
	}
	return nil
}

// updateECS file from template and given ECS version
func updateECS() error {
	fmt.Println("Update ECS Types...")
	var ecsBranch = os.Getenv("ECS_BRANCH")
	if ecsBranch == "" {
		return errors.New("ECS_BRANCH must be specified")
	}
	tmpDir := filepath.Join("internal", "tmp")
	ecsDir := filepath.Join(tmpDir, "ecs")
	for _, cmd := range []*exec.Cmd{
		exec.Command("rm", "-rf", ecsDir),
		exec.Command("mkdir", "-p", tmpDir),
		exec.Command("git", "clone", "https://github.com/elastic/ecs",
			"-b", ecsBranch, ecsDir),
	} {
		if err := cmd.Run(); err != nil {
			return err
		}
	}
	b, err := ioutil.ReadFile(filepath.Join(ecsDir, "version"))
	if err != nil {
		return err
	}
	cmd := exec.Command("go-ecsfieldgen",
		"-out", "ecs.go",
		"-version", strings.TrimRight(string(b), "\n"),
		"-pkg", "ecszap",
		"-template", filepath.Join("internal", "template"),
		filepath.Join(ecsDir, "generated", "ecs", "ecs_flat.yml"))
	fmt.Println(cmd.String())
	return cmd.Run()
}
