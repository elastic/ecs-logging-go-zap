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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestJSONEncoder(t *testing.T) {
	enc := NewJSONEncoder(zap.NewDevelopmentEncoderConfig())
	entry := zapcore.Entry{
		Level:   zapcore.DebugLevel,
		Time:    time.Unix(1583484083, 953467845),
		Message: "log message",
	}
	fields := []zapcore.Field{
		zap.String("foo", "bar"),
		zap.Int("count", 8),
	}
	buf, err := enc.EncodeEntry(entry, fields)
	require.NoError(t, err)
	expected := `{
		"log.level": "DEBUG",
		"@timestamp": 1583484083953468,
		"message": "log message",
		"ecs.version": "1.5.0",
		"foo": "bar",
		"count": 8
	}`
	assert.JSONEq(t, expected, buf.String())
}
