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
	"bytes"
	"errors"
	"runtime"
	"testing"

	pkgerrors "github.com/pkg/errors"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func BenchmarkCore(b *testing.B) {
	fields := []zapcore.Field{
		zap.String("str", "foo"),
		zap.Int64("int64-1", 1),
		zap.Int64("int64-2", 2),
		zap.Float64("float64", 1.0),
		zap.String("string1", "\n"),
		zap.String("string2", "🙊"),
		zap.Bool("bool", true),
	}
	cores := map[string]func(ws zapcore.WriteSyncer) zapcore.Core{
		"zap": func(ws zapcore.WriteSyncer) zapcore.Core {
			enc := zapcore.NewJSONEncoder(zap.NewDevelopmentEncoderConfig())
			return zapcore.NewCore(enc, ws, zap.DebugLevel)
		},
		"ecs": func(ws zapcore.WriteSyncer) zapcore.Core {
			return NewCore(NewDefaultEncoderConfig(), ws, zap.DebugLevel)
		},
	}

	for name, new := range cores {
		b.Run(name+"/fields", func(b *testing.B) {
			out := testWriteSyncer{}
			core := new(&out)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				core.Write(zapcore.Entry{
					Message: "fake",
					Level:   zapcore.DebugLevel,
				}, fields)
				out.reset()
			}
		})

		b.Run(name+"/caller", func(b *testing.B) {
			caller := zapcore.NewEntryCaller(runtime.Caller(0))
			out := testWriteSyncer{}
			core := new(&out)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				core.Write(zapcore.Entry{
					Message: "fake",
					Level:   zapcore.DebugLevel,
					Caller:  caller,
				}, fields)
				out.reset()
			}
		})

		b.Run(name+"/errors", func(b *testing.B) {
			err1 := errors.New("boom")
			err2 := pkgerrors.Wrap(err1, "crash")
			err3 := testErr{msg: "boom/crash", errors: []error{err1, err2}}
			fieldsWithErr := append(fields,
				zap.Error(err1),
				zap.Error(err2),
				zap.Error(err3),
			)
			out := testWriteSyncer{}
			core := new(&out)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				core.Write(zapcore.Entry{
					Message: "fake",
					Level:   zapcore.DebugLevel,
				}, fieldsWithErr)
				out.reset()
			}
		})
	}
}

type testWriteSyncer struct {
	b bytes.Buffer
}

func (o *testWriteSyncer) Write(p []byte) (int, error) {
	return o.b.Write(p)
}

func (o *testWriteSyncer) Sync() error { return nil }

func (o *testWriteSyncer) reset() { o.b.Reset() }

type testErr struct {
	msg    string
	errors []error
}

func (e testErr) Error() string {
	return e.msg
}
func (e testErr) Errors() []error {
	return e.errors
}
