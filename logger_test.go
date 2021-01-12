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
	"errors"
	"testing"

	"go.uber.org/zap/zapcore"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type testOutput struct {
	m map[string]interface{}
}

func (tw *testOutput) Write(p []byte) (int, error) {
	err := json.Unmarshal(p, &tw.m)
	return len(p), err
}

func (tw *testOutput) Sync() error { return nil }

func (tw *testOutput) requireContains(t *testing.T, keys []string) {
	for _, s := range keys {
		require.Contains(t, tw.m, s)
	}
}

func (tw *testOutput) reset() {
	tw.m = make(map[string]interface{})
}

func TestECSZapLogger_With(t *testing.T) {
	out := testOutput{}

	for _, tc := range []struct {
		name string
		core zapcore.Core
	}{
		{name: "newCoreFromConfig",
			core: NewCore(NewDefaultEncoderConfig(), &out, zap.DebugLevel)},
		{name: "wrappedCore",
			core: func() zapcore.Core {
				ecsEncCfg := ECSCompatibleEncoderConfig(zap.NewProductionEncoderConfig())
				enc := zapcore.NewJSONEncoder(ecsEncCfg)
				core := zapcore.NewCore(enc, &out, zap.DebugLevel)
				return WrapCore(core)
			}()},
	} {
		t.Run(tc.name, func(t *testing.T) {

			logger := zap.New(tc.core, zap.AddCaller())
			defer logger.Sync()

			// strongly typed fields
			logger.Info("testlog", zap.String("foo", "bar"))
			out.requireContains(t, []string{"ecs.version", "message",
				"@timestamp", "log.level", "log.origin", "foo"})

			// log a wrapped error
			out.reset()
			logger.With(zap.Error(errors.New("test error"))).Error("boom")
			out.requireContains(t, []string{"error", "message"})
			assert.Equal(t, "boom", out.m["message"])
			outErr, ok := out.m["error"].(map[string]interface{})
			require.True(t, ok, out.m["error"])
			assert.Equal(t, map[string]interface{}{"message": "test error"}, outErr)

			// Adding logger wide fields and a logger name
			out.reset()
			logger = logger.With(zap.String("foo", "bar"))
			logger = logger.Named("mylogger")
			logger.Debug("debug message")
			out.requireContains(t, []string{"log.logger", "foo"})

			// Use loosely typed logger
			out.reset()
			sugar := logger.Sugar()
			sugar.Infow("some logging info",
				"foo", "bar",
				"count", 17,
			)
			out.requireContains(t, []string{"ecs.version", "message",
				"@timestamp", "log.level", "log.origin", "foo", "count"})

			out.reset()
		})
	}
}
