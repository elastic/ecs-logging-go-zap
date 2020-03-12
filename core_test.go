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

package ecszap

import (
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"go.uber.org/zap/zapcore"

	"go.uber.org/zap"
)

func TestCore(t *testing.T) {
	c := NewCore(NewDefaultEncoderConfig(), os.Stdout, zap.DebugLevel)
	fields := []zapcore.Field{
		zap.String("foo", "bar"),
		zap.Error(errors.New("boom")),
	}
	c = c.With(fields)
	s := c.(*core).enc.(*jsonEncoder).buf.String()
	// when calling internal implementation of addFields fields will be stored in ECS format
	for _, k := range []string{"ecs.version", "error.message", "foo"} {
		assert.Contains(t, s, k)
	}
}
