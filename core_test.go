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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestCore(t *testing.T) {
	entry := zapcore.Entry{Level: zapcore.DebugLevel}
	fields := []zapcore.Field{
		zap.String("foo", "bar"),
		zap.Error(errors.New("boom")),
	}
	assertLogged := func(t *testing.T, out testOutput) {
		out.requireContains(t, []string{"error", "foo"})
		outErr, ok := out.m["error"].(map[string]interface{})
		require.True(t, ok, out.m)
		assert.Equal(t, map[string]interface{}{"message": "boom"}, outErr)
		assert.Equal(t, "bar", out.m["foo"])
	}

	t.Run("With", func(t *testing.T) {
		out := testOutput{}
		c := NewCore(NewDefaultEncoderConfig(), &out, zap.DebugLevel)
		c = c.With(fields)
		require.NoError(t, c.Write(entry, nil))
		assertLogged(t, out)
	})

	t.Run("Write", func(t *testing.T) {
		out := testOutput{}
		c := NewCore(NewDefaultEncoderConfig(), &out, zap.DebugLevel)
		require.NoError(t, c.Write(entry, fields))
		assertLogged(t, out)
	})

	t.Run("Check", func(t *testing.T) {
		out := testOutput{}
		c := NewCore(NewDefaultEncoderConfig(), &out, zap.DebugLevel)
		ce := c.Check(entry, &zapcore.CheckedEntry{})
		ce.Write(fields...)
		assertLogged(t, out)
	})
}
