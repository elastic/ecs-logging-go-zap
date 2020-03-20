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
	"fmt"
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
			expected: `"log.origin": {
							"file.line": 30,
							"file.name": "ecs-logging-go-zap/json_encoder_test.go"
						},
						"log.origin.stacktrace": "stacktrace frames",
						"log.logger": "ECS",`},
		{name: "defaultUnmarshal",
			input:    "",
			expected: ``},
		{name: "shortCaller",
			input: `{"lineEnding": "\n",
					 "nameEncoder": "full",
					 "levelEncoder": "upper",
				 	 "durationEncoder": "ms",
					 "callerEncoder": "short",
					 "enableCaller":true}`,
			expected: `"log.origin": {
							"file.line": 30,
							"file.name": "ecs-logging-go-zap/json_encoder_test.go"
						},`},
		{name: "fullCaller",
			input: `{"callerEncoder": "full","enableCaller":true}`,
			expected: `"log.origin": {
							"file.line": 30,
							"file.name": "/Home/foo/coding/ecs-logging-go-zap/json_encoder_test.go"
						},`},
		{name: "enabled",
			input: `{"enableName": true, "enableStacktrace": true, "enableCaller":true}`,
			expected: `"log.origin": {
							"file.line": 30,
							"file.name": "ecs-logging-go-zap/json_encoder_test.go"
						},
						"log.origin.stacktrace": "stacktrace frames",
						"log.logger": "ECS",`},
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
				Service.Name("serviceA"),
				Service.Version("2.1.3"),
			}
			expected := fmt.Sprintf(`{
					%v
					"log.level": "debug",
					"@timestamp": 1583484083953468,
					"message": "log message",
					"ecs.version": "%s",
					"foo": "bar",
					"count": 8,
					"service.name": "serviceA",
					"service.version":"2.1.3"
				}`, tc.expected, Version)

			//parse config and encode
			cfg := tc.cfg
			if tc.input != "" {
				require.NoError(t, json.Unmarshal([]byte(tc.input), &cfg))
			}
			enc := NewJSONEncoder(cfg).(*jsonEncoder)
			buf, err := enc.EncodeEntry(entry, fields)
			require.NoError(t, err)
			out := buf.String()
			assert.JSONEq(t, expected, out)
		})
	}
}

func TestJsonEncoder_Clone(t *testing.T) {
	enc := NewJSONEncoder(NewDefaultEncoderConfig())
	encClone := enc.Clone()
	assert.NotSame(t, enc, encClone)
	assert.NotSame(t, &enc.(*jsonEncoder).Encoder, &encClone.(*jsonEncoder).Encoder)
}
