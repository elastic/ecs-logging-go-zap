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
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type tenc struct {
	enc    *jsonEncoder
	entry  zapcore.Entry
	fields []zapcore.Field
}

func setup(cfg EncoderConfig) tenc {
	return tenc{
		enc: newJSONEncoder(cfg).(*jsonEncoder),
		entry: zapcore.Entry{
			Level:      zapcore.DebugLevel,
			Time:       time.Unix(1583484083, 953467845),
			Message:    "log message",
			Caller:     zapcore.NewEntryCaller(runtime.Caller(0)),
			Stack:      "stacktrace frames",
			LoggerName: "ECS",
		},
		fields: []zapcore.Field{
			zap.String("foo", "bar"),
			zap.Int("count", 8),
			zap.Error(errors.New("boom")),
		}}
}

func TestJSONEncoder(t *testing.T) {
	for _, tc := range []struct {
		name     string
		cfg      EncoderConfig
		expected string
	}{
		{name: "full",
			cfg: NewDefaultEncoderConfig(),
			expected: `{"log.level": "debug",
						"@timestamp": 1583484083953468,
						"message": "log message",
						"ecs.version": "1.5.0",
						"log.origin.file.line": 45,
						"log.origin.file.name": "ecs-logging-go-zap/json_encoder_test.go",
						"log.origin.stacktrace": "stacktrace frames",
						"log.logger": "ECS",
						"foo": "bar",
						"count": 8,
						"error.message": "boom"}`},
		{name: "skip",
			cfg: func() EncoderConfig {
				c := NewDefaultEncoderConfig()
				c.SkipName = true
				c.SkipStacktrace = true
				c.SkipCaller = true
				return c
			}(),
			expected: `{"log.level": "debug",
						"@timestamp": 1583484083953468,
						"message": "log message",
						"ecs.version": "1.5.0",
						"foo": "bar",
						"count": 8,
						"error.message": "boom"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			te := setup(tc.cfg)
			buf, err := te.enc.EncodeEntry(te.entry, te.fields)
			require.NoError(t, err)
			assert.JSONEq(t, tc.expected, buf.String())
		})
	}
}
