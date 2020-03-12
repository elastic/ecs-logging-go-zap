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

	errs "github.com/pkg/errors"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func BenchmarkJSONEnc(b *testing.B) {
	fields := []zapcore.Field{
		zap.String("str", "foo"),
		zap.Int64("int64-1", 1),
		zap.Int64("int64-2", 2),
		zap.Float64("float64", 1.0),
		zap.String("string1", "\n"),
		zap.String("string2", "🙊"),
		zap.Bool("bool", true),
	}
	err1 := errors.New("boom")
	err2 := errs.Wrap(err1, "crash")
	err3 := multiErr{msg: "boom/crash", errors: []error{err1, err2}}
	fieldsWithErr := append(fields,
		zap.Error(err1),
		zap.Error(err2),
		zap.Error(err3))
	caller := zapcore.NewEntryCaller(runtime.Caller(0))
	zapEncConfig := zap.NewDevelopmentEncoderConfig()
	encConfig := NewDefaultEncoderConfig()

	for name, enc := range map[string]zapcore.Encoder{
		"zapcore": zapcore.NewJSONEncoder(zapEncConfig),
		"ecszap":  newJSONEncoder(encConfig),
	} {
		b.ResetTimer()

		b.Run(name+"/fields", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				buf, _ := enc.EncodeEntry(zapcore.Entry{
					Message: "fake",
					Level:   zapcore.DebugLevel,
				}, fields)
				buf.Free()
			}
		})

		b.Run(name+"/caller", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				buf, _ := enc.EncodeEntry(zapcore.Entry{
					Message: "fake",
					Level:   zapcore.DebugLevel,
					Caller:  caller,
				}, fields)
				buf.Free()
			}
		})

		b.Run(name+"/errors", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				buf, _ := enc.EncodeEntry(zapcore.Entry{
					Message: "fake",
					Level:   zapcore.DebugLevel,
					Caller:  caller,
				}, fieldsWithErr)
				buf.Free()
			}
		})
	}
}
