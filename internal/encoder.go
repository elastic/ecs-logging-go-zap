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

package internal

import (
	"strings"
	"time"

	"go.uber.org/zap/zapcore"
)

func EpochMicrosTimeEncoder(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
	micros := float64(t.UnixNano()) / float64(time.Microsecond)
	enc.AppendFloat64(micros)
}

type caller struct {
	zapcore.EntryCaller
	fullPath bool
}

func (c *caller) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	var file string
	if c.fullPath {
		file = c.File
	} else {
		file = c.TrimmedPath()
		file = file[:strings.LastIndex(file, ":")]
	}
	enc.AddString("file.name", file)
	enc.AddInt("file.line", c.Line)
	return nil
}

type CallerEncoder func(zapcore.EntryCaller, zapcore.PrimitiveArrayEncoder)

// FullCallerEncoder serializes the file name and line from the caller
// in an ECS compliant way; serializing the full path of the file name
// using the underlying zapcore.EntryCaller.
func FullCallerEncoder(c zapcore.EntryCaller, enc zapcore.PrimitiveArrayEncoder) {
	encodeCaller(&caller{c, true}, enc)
}

// ShortCallerEncoder serializes the file name and line from the caller
// in an ECS compliant way; removing everything except the final directory from the
// file name by calling the underlying zapcore.EntryCaller TrimmedPath().
func ShortCallerEncoder(c zapcore.EntryCaller, enc zapcore.PrimitiveArrayEncoder) {
	encodeCaller(&caller{c, false}, enc)
}

// UnmarshalText creates a CallerEncoder function,
// `full` is unmarshalled to FullCallerEncoder,
// defaults to ShortCallerEncoder,
func (e *CallerEncoder) UnmarshalText(text []byte) error {
	switch string(text) {
	case "full":
		*e = FullCallerEncoder
	default:
		*e = ShortCallerEncoder
	}
	return nil
}

func encodeCaller(c *caller, enc zapcore.PrimitiveArrayEncoder) {
	// this function can only be called internally so we have full control over it
	// and can ensure that enc is always of type zapcore.ArrayEncoder
	if e, ok := enc.(zapcore.ArrayEncoder); ok {
		e.AppendObject(c)
	}
}
