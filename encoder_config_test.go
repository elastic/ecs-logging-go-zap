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
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestJSONEncoder_EncoderConfig(t *testing.T) {
	path := "/Home/foo/coding/ecszap/json_encoder_test.go"
	caller := zapcore.NewEntryCaller(0, path, 30, true)
	caller.Function = "FuncName"

	for _, tc := range []struct {
		name     string
		cfg      EncoderConfig
		input    string
		expected string
	}{
		{name: "defaultConfig",
			cfg: NewDefaultEncoderConfig(),
			expected: `{"log.level": "debug",
						"@timestamp": "2020-09-13T10:48:03.000Z",
						"message": "log message",
						"log.origin": {
							"file.line": 30,
							"file.name": "ecszap/json_encoder_test.go",
							"function": "FuncName"
						},
						"log.origin.stack_trace": "frames",
						"log.logger": "ECS",
						"foo": "bar",
						"dur": 5000000}`},
		{name: "customizedDisabled",
			cfg: EncoderConfig{
				EnableName:       false,
				EnableCaller:     false,
				EnableStackTrace: false,
			},
			expected: `{"log.level": "debug",
						"@timestamp": "2020-09-13T10:48:03.000Z",
						"message": "log message",
						"foo": "bar",
						"dur": 5000000}`},
		{name: "customized",
			cfg: EncoderConfig{
				EnableName:       true,
				EnableCaller:     true,
				EnableStackTrace: true,
				EncodeName: func(loggerName string, enc zapcore.PrimitiveArrayEncoder) {
					enc.AppendString(strings.ToLower(loggerName))
				},
				EncodeLevel:    zapcore.CapitalLevelEncoder,
				EncodeDuration: zapcore.MillisDurationEncoder,
				EncodeCaller:   ShortCallerEncoder,
			},
			expected: `{"log.level": "DEBUG",
						"@timestamp": "2020-09-13T10:48:03.000Z",
						"message": "log message",
						"log.origin": {
							"file.line": 30,
							"file.name": "ecszap/json_encoder_test.go",
							"function": "FuncName"
						},
						"log.origin.stack_trace": "frames",
						"log.logger": "ecs",
						"foo": "bar",
						"dur": 5}`},
		{name: "defaultUnmarshal",
			expected: `{"log.level": "debug",
						"@timestamp": "2020-09-13T10:48:03.000Z",
						"message": "log message",
						"foo": "bar",
						"dur": 5000000}`},
		{name: "allEnabled",
			input: `{"enableName": true, 
  					 "enableStackTrace": true,
					 "enableCaller":true,
					 "levelEncoder": "upper",
				 	 "durationEncoder": "ms",
					 "callerEncoder": "short"}`,
			expected: `{"log.level": "debug",
						"@timestamp": "2020-09-13T10:48:03.000Z",
						"message": "log message",
						"log.origin": {
							"file.line": 30,
							"file.name": "ecszap/json_encoder_test.go",
							"function": "FuncName"
						},
						"log.origin.stack_trace": "frames",
						"log.logger": "ECS",
						"foo": "bar",
						"dur": 5}`},
		{name: "fullCaller",
			input: `{"callerEncoder": "full","enableCaller":true}`,
			expected: `{"log.level": "debug",
						"@timestamp": "2020-09-13T10:48:03.000Z",
						"message": "log message",
						"log.origin": {
							"file.line": 30,
							"file.name": "/Home/foo/coding/ecszap/json_encoder_test.go",
							"function": "FuncName"
						},
						"foo": "bar",
						"dur": 5000000}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// setup
			entry := zapcore.Entry{
				Level:      zapcore.DebugLevel,
				Time:       time.Unix(1599994083, 0).UTC(),
				Message:    "log message",
				Caller:     caller,
				Stack:      "frames",
				LoggerName: "ECS",
			}
			fields := []zapcore.Field{
				zap.String("foo", "bar"),
				zap.Duration("dur", 5*time.Millisecond),
			}
			cfg := tc.cfg
			if tc.input != "" {
				require.NoError(t, json.Unmarshal([]byte(tc.input), &cfg))
			}
			enc := zapcore.NewJSONEncoder(cfg.ToZapCoreEncoderConfig())

			//encode entry and ensure JSONEncoder configurations are properly applied
			buf, err := enc.EncodeEntry(entry, fields)
			require.NoError(t, err)
			out := buf.String()
			assert.JSONEq(t, tc.expected, out)
		})
	}
}

func TestECSCompatibleEncoderConfig(t *testing.T) {
	path := "/Home/foo/coding/ecszap/json_encoder_test.go"
	caller := zapcore.NewEntryCaller(0, path, 30, true)
	caller.Function = "FuncName"

	for _, tc := range []struct {
		name     string
		cfg      zapcore.EncoderConfig
		expected string
	}{
		{name: "empty config",
			cfg: zapcore.EncoderConfig{},
			expected: `{"log.level": "debug",
						"@timestamp": "2020-09-13T10:48:03.000Z",
						"message": "log message",
						"foo": "bar",
						"count": 8}`},
		{name: "withKeys",
			cfg: zapcore.EncoderConfig{
				MessageKey: "replaced messageKey", LevelKey: "replaced levelKey",
				TimeKey: "replaced timeKey", EncodeTime: zapcore.EpochMillisTimeEncoder,
				NameKey: "replaced nameKey", StacktraceKey: "replaced stackTraceKey",
				CallerKey: "replaced callerKey", EncodeLevel: zapcore.CapitalLevelEncoder},
			expected: `{"log.level": "DEBUG",
						"@timestamp": "2020-09-13T10:48:03.000Z",
						"message": "log message",
						"log.origin": {
							"file.line": 30,
							"file.name": "ecszap/json_encoder_test.go",
							"function": "FuncName"
						},
						"log.origin.stack_trace": "frames",
						"log.logger": "ECS",
						"foo": "bar",
						"count": 8}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// setup
			entry := zapcore.Entry{
				Level:      zapcore.DebugLevel,
				Time:       time.Unix(1599994083, 0).UTC(),
				Message:    "log message",
				Caller:     caller,
				Stack:      "frames",
				LoggerName: "ECS",
			}
			fields := []zapcore.Field{
				zap.String("foo", "bar"),
				zap.Int("count", 8),
			}

			ecsCfg := ECSCompatibleEncoderConfig(tc.cfg)
			//parse config and create encoder from it
			enc := zapcore.NewJSONEncoder(ecsCfg)

			//encode entry and ensure JSONEncoder configurations are properly applied
			buf, err := enc.EncodeEntry(entry, fields)
			require.NoError(t, err)
			out := buf.String()
			assert.JSONEq(t, tc.expected, out)
		})
	}
}
