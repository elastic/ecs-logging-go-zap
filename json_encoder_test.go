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
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestJSONEncoder_EncodeEntry(t *testing.T) {
	path := "/Home/foo/coding/ecs-logging-go-zap/json_encoder_test.go"
	caller := zapcore.NewEntryCaller(0, path, 30, true)
	for _, tc := range []struct {
		name     string
		cfg      EncoderConfig
		input    string
		expected string
	}{
		{name: "defaultConfig",
			cfg: NewDefaultEncoderConfig(),
			expected: `{"log.level": "debug",
						"@timestamp": 1583484083953468,
						"message": "log message",
						"ecs.version": "1.5.0",
						"log.origin": {
							"file.line": 30,
							"file.name": "ecs-logging-go-zap/json_encoder_test.go"
						},
						"log.origin.stacktrace": "stacktrace frames",
						"log.logger": "ECS",
						"foo": "bar",
						"count": 8}`},
		{name: "defaultUnmarshal",
			input: "",
			expected: `{"log.level": "debug",
						"@timestamp": 1583484083953468,
						"message": "log message",
						"ecs.version": "1.5.0",
						"foo": "bar",
						"count": 8}`},
		{name: "shortCaller",
			input: `{"lineEnding": "\n",
					 "nameEncoder": "full",
					 "levelEncoder": "upper",
				 	 "durationEncoder": "ms",
					 "callerEncoder": "short"}`,
			expected: `{"log.level": "debug",
						"@timestamp": 1583484083953468,
						"message": "log message",
						"ecs.version": "1.5.0",
						"foo": "bar",
						"count": 8}`},
		{name: "fullCaller",
			input: `{"callerEncoder": "full"}`,
			expected: `{"log.level": "debug",
						"@timestamp": 1583484083953468,
						"message": "log message",
						"ecs.version": "1.5.0",
						"foo": "bar",
						"count": 8}`},
		{name: "enabled",
			input: `{"enableName": true, "enableStacktrace": true, "enableCaller":true}`,
			expected: `{"log.level": "debug",
						"@timestamp": 1583484083953468,
						"message": "log message",
						"ecs.version": "1.5.0",
						"log.origin": {
							"file.line": 30,
							"file.name": "ecs-logging-go-zap/json_encoder_test.go"
						},
						"log.origin.stacktrace": "stacktrace frames",
						"log.logger": "ECS",
						"foo": "bar",
						"count": 8}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// setup
			entry := zapcore.Entry{
				Level:      zapcore.DebugLevel,
				Time:       time.Unix(1583484083, 953467845),
				Message:    "log message",
				Caller:     caller,
				Stack:      "stacktrace frames",
				LoggerName: "ECS",
			}
			fields := []zapcore.Field{
				zap.String("foo", "bar"),
				zap.Int("count", 8),
			}
			//parse config and create encoder from it
			cfg := tc.cfg
			if tc.input != "" {
				require.NoError(t, json.Unmarshal([]byte(tc.input), &cfg))
			}
			enc := NewJSONEncoder(cfg).(*jsonEncoder)

			//encode entry and ensure JSONEncoder configurations are properly applied
			buf, err := enc.EncodeEntry(entry, fields)
			require.NoError(t, err)
			out := buf.String()
			assert.JSONEq(t, tc.expected, out)
		})
	}
}

func TestJsonEncoder_Clone(t *testing.T) {
	enc := NewJSONEncoder(NewDefaultEncoderConfig())
	encClone := enc.Clone()
	assert.NotSame(t, enc, encClone)
	assert.NotSame(t, &enc.(*jsonEncoder).Encoder, &encClone.(*jsonEncoder).Encoder)
}
