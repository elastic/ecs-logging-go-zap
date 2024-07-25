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

package spec

import (
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"runtime"

	"github.com/pkg/errors"
)

var (
	// V1 holds the v1 specification
	V1 *Spec
)

// Spec holds the fields specified for a spec version
type Spec struct {
	URL string `json:"url"`
	ECS struct {
		Version string `json:"version"`
	} `json:"ecs"`
	Fields map[string]Field `json:"fields"`
}

// Field contains requirements for a log field
type Field struct {
	Comment       Comment      `json:"comment"`
	Default       string       `json:"default"`
	Index         *int         `json:"index"`
	Required      bool         `json:"required"`
	Sanitization  Sanitization `json:"sanitization"`
	TopLevelField bool         `json:"top_level_field"`
	Type          string       `json:"type"`
	URL           string       `json:"url"`
}

// Comment is an array of strings
type Comment []string

// Sanitization defines a substitute for certain substrings
type Sanitization struct {
	Key struct {
		Replacements []string `json:"replacements"`
		Substitute   string   `json:"substitute"`
	} `json:"key"`
}

// RequiredFields returns all fields that are defined as required
func (s *Spec) RequiredFields() []string {
	var requiredKeys []string
	for name, field := range s.Fields {
		if field.Required {
			requiredKeys = append(requiredKeys, name)
		}
	}
	return requiredKeys
}

// UnmarshalJSON unmarshals the given byte into a Comment.
// Valid values are strings and arrays of strings
func (c *Comment) UnmarshalJSON(b []byte) error {
	var comments []string
	if err := json.Unmarshal(b, &comments); err != nil {
		var comment string
		if err := json.Unmarshal(b, &comment); err != nil {
			return errors.Wrap(err, "unmarshaling comment(s)")
		}
		comments = []string{comment}
	}
	*c = comments
	return nil
}

func init() {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		panic("cannot recover information from runtime.Caller")
	}
	f := path.Join(filepath.ToSlash(filepath.Dir(filename)), "v1.json")
	b, err := os.ReadFile(f)
	if err != nil {
		panic(errors.Wrap(err, "reading spec version 1 failed"))
	}
	if err := json.Unmarshal(b, &V1); err != nil {
		panic(errors.Wrap(err, "initializing spec version 1 failed"))
	}
}
