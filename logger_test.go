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
	"fmt"
	"strconv"
	"testing"
	"time"

	"go.elastic.co/ecszap/internal/spec"
	"go.uber.org/zap/zapcore"

	errs "github.com/pkg/errors"

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

func (tw *testOutput) validate(t *testing.T, keys []string) {
	for _, s := range keys {
		require.Contains(t, tw.m, s)
	}

	// Fields `log.origin.file.line` and `log.origin.file.name` are logged as
	// a map under key log.origin. By using the zap jsonEncoder this cannot
	// be changed. Remove the nested and add a dotted version of the fields
	if caller, ok := tw.m[callerKey].(map[string]interface{}); ok {
		for name, val := range caller {
			tw.m[fmt.Sprintf("%s.%s", callerKey, name)] = val
			delete(tw.m, name)
		}
	}
	// skip index checks as we do not have control over that with the formatter
	// skip Default value checks as they are not yet implemented
	// skip TopLevelField check as ecszap logger logs in dot notation anyways
	// skip Sanitization as it is not implemented yet
	for name, val := range tw.m {
		field, ok := spec.V1.Fields[name]
		if !ok { // custom field not defined in spec
			continue
		}
		if field.Required { // all required fields must be present in the log line
			require.Contains(t, tw.m, name)
			require.NotNil(t, tw.m[name])
		}
		if field.Type != "" { // the defined type must be met
			var ok bool
			switch field.Type {
			case "string":
				_, ok = val.(string)
			case "datetime":
				var s string
				s, ok = val.(string)
				if _, err := time.Parse("2006-01-02T15:04:05.000Z0700", s); err == nil {
					ok = true
				}
			case "integer":
				// json.Unmarshal unmarshals into float64 instead of int
				if _, floatOK := val.(float64); floatOK {
					_, err := strconv.ParseInt(fmt.Sprintf("%v", val), 10, 64)
					if err == nil {
						ok = true
					}
				}
			default:
				panic(fmt.Errorf("unhandled type %s from specification for field %s", field.Type, name))
			}
			require.True(t, ok, fmt.Sprintf("%s: %v", name, val))
		}
	}
}

func (tw *testOutput) reset() {
	tw.m = make(map[string]interface{})
}

func TestECSZapLogger(t *testing.T) {
	out := testOutput{}

	for _, tc := range []struct {
		name string
		core zapcore.Core
	}{
		{name: "newCoreFromConfig",
			core: NewCore(NewDefaultEncoderConfig(), &out, zap.DebugLevel)},
		{name: "",
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
			out.validate(t, []string{"foo", "log.origin"})

			// log a wrapped error
			out.reset()
			err := errors.New("boom")
			logger.Error("some error", zap.Error(errs.Wrap(err, "crash")))
			out.validate(t, []string{"error"})

			// Adding logger wide fields and a logger name
			out.reset()
			logger = logger.With(zap.String("foo", "bar"))
			logger = logger.With(zap.Error(errors.New("wrapCore Error")))
			logger = logger.Named("mylogger")
			logger.Debug("debug message")
			out.validate(t, []string{"foo", "error"})

			// Use loosely typed logger
			out.reset()
			sugar := logger.Sugar()
			sugar.Infow("some logging info",
				"foo", "bar",
				"count", 17,
			)
			out.validate(t, []string{"log.origin", "foo", "count"})
			out.reset()

		})
	}
	// Wrapped logger
	out.reset()
	cfg := ECSCompatibleEncoderConfig(zap.NewProductionEncoderConfig())
	encoder := zapcore.NewJSONEncoder(cfg)
	core := zapcore.NewCore(encoder, &out, zap.DebugLevel)
	logger := zap.New(WrapCore(core), zap.AddCaller())
	defer logger.Sync()
	logger.With(zap.Error(errors.New("wrapCore"))).Error("boom")
	out.validate(t, []string{"message", "error"})
	assert.Equal(t, "boom", out.m["message"])
	outErr, ok := out.m["error"].(map[string]interface{})

	require.True(t, ok, out.m["error"])
	assert.Equal(t, map[string]interface{}{"message": "wrapCore"}, outErr)
}
