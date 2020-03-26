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

	if err := generateECS(); err != nil {
		return err
	}
	return runCmds([]*exec.Cmd{
		exec.Command("go-licenser", "."),
		exec.Command("go", "fmt"),
		exec.Command("go", "mod", "tidy"),
	})
}

// Install development dependencies
func InstallDeps() error {
	fmt.Println("Installing Deps...")
	return runCmds([]*exec.Cmd{
		exec.Command("go", "get", "github.com/elastic/go-licenser"),
		exec.Command("go", "get", "github.com/urso/go-ecsfieldgen"),
	})
}

// generateECS file from template and given ECS version
func generateECS() error {
	fmt.Println("Generate ECS information...")
	var ecsVersion = os.Getenv("ECS_VERSION")
	if ecsVersion == "" {
		return errors.New("ECS_VERSION must be specified")
	}
	tmpDir := filepath.Join("internal", "tmp")
	tmpECSDir := filepath.Join(tmpDir, "ecs")
	if err := runCmds([]*exec.Cmd{
		exec.Command("rm", "-rf", tmpECSDir),
		exec.Command("mkdir", "-p", tmpDir),
		exec.Command("git", "clone", "https://github.com/elastic/ecs",
			"-b", ecsVersion, tmpECSDir),
	}); err != nil {
		return err
	}
	b, err := ioutil.ReadFile(filepath.Join(tmpECSDir, "version"))
	if err != nil {
		return err
	}
	version := strings.TrimRight(string(b), "\n")
	schema := filepath.Join(tmpECSDir, "generated", "ecs", "ecs_flat.yml")
	return runCmds([]*exec.Cmd{
		generateECSVersion(version, schema),
		generateECSTypes(version, schema),
		exec.Command("go", "fmt", "./..."),
		exec.Command("rm", "-rf", tmpECSDir),
	})
}

func generateECSVersion(version string, schema string) *exec.Cmd {
	return exec.Command("go-ecsfieldgen",
		"-out", "version.go",
		"-version", version,
		"-pkg", "ecszap",
		"-template", filepath.Join("internal", "version.go.tmpl"),
		schema,
	)
}

func generateECSTypes(version string, schema string) *exec.Cmd {
	return exec.Command("go-ecsfieldgen",
		"-out", filepath.Join("ecs", "ecs.go"),
		"-version", version,
		"-pkg", "ecs",
		"-template", filepath.Join("internal", "ecs.go.tmpl"),
		schema,
	)
}

func runCmds(cmds []*exec.Cmd) error {
	for _, cmd := range cmds {
		if err := cmd.Run(); err != nil {
			fmt.Println(fmt.Sprintf("%s: %+w", cmd.String(), err))
			return err
		}
	}
	return nil
}
