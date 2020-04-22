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
	"go.uber.org/zap/zapcore"

	"github.com/elastic/ecs-logging-go-zap/internal"
)

// NewCore creates a zapcore.Core that uses an ECS conformant JSON encoder.
// Internally it makes use of zapcore.Core functionality,
// and only implements dedicated parts required to be aligned with ECS.
func NewCore(cfg EncoderConfig, ws zapcore.WriteSyncer, enab zapcore.LevelEnabler) zapcore.Core {
	return WrapCore(zapcore.NewCore(NewJSONEncoder(cfg), ws, enab))
}

// WrapCore wraps a given core with the ecszap.core functionality
func WrapCore(c zapcore.Core) zapcore.Core {
	return &core{c}
}

type core struct {
	zapcore.Core
}

// With converts error fields into ECS compliant errors
// and calls the internal zapcore.Core for adding structured context.
func (c core) With(fields []zapcore.Field) zapcore.Core {
	convertToECSFields(fields)
	return &core{c.Core.With(fields)}
}

// Check verifies whether or not the provided entry should be logged,
// by comparing the log level with the configured log level in the core.
// If it should be logged the core is added to the returned entry.
func (c core) Check(ent zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(ent.Level) {
		return ce.AddCore(ent, c)
	}
	return ce
}

// Write converts error fields into ECS compliant errors
// and calls the internal zapcore.Core for serializing the entry and fields.
func (c core) Write(ent zapcore.Entry, fields []zapcore.Field) error {
	convertToECSFields(fields)
	return c.Core.Write(ent, fields)
}

func convertToECSFields(fields []zapcore.Field) {
	for i, f := range fields {
		if f.Type == zapcore.ErrorType {
			fields[i] = zapcore.Field{Key: "error",
				Type:      zapcore.ObjectMarshalerType,
				Interface: internal.NewError(f.Interface.(error)),
			}
		}
	}
}
