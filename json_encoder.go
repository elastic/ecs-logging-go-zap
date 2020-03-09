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

package main

import (
	"time"

	"go.uber.org/zap"

	"go.uber.org/zap/buffer"
	"go.uber.org/zap/zapcore"
)

const ECSJSONEncoding = "ecsjson"

const version = "1.5.0"

func init() {
	zap.RegisterEncoder(ECSJSONEncoding, func(encoderConfig zapcore.EncoderConfig) (zapcore.Encoder, error) {
		return NewECSJSONEncoder(encoderConfig), nil
	})
}

type jsonEncoder struct {
	zapjsonEncoder zapcore.Encoder
}

// NewECSJSONEncoder creates a JSON encoder,
// populating a minimal set of Elastic common schema (ECS) values.
// The ECSJSONEncoder uses zap.JSONEncoder internally.
func NewECSJSONEncoder(cfg zapcore.EncoderConfig) zapcore.Encoder {
	cfg.MessageKey = "message"
	cfg.LevelKey = "log.level"
	cfg.TimeKey = "@timestamp"
	cfg.EncodeTime = epochMicrosTimeEncoder

	enc := jsonEncoder{zapjsonEncoder: zapcore.NewJSONEncoder(cfg)}
	enc.AddString("ecs.version", version)
	return &enc
}

func (enc *jsonEncoder) Clone() zapcore.Encoder {
	clone := &jsonEncoder{}
	clone.zapjsonEncoder = enc.zapjsonEncoder.Clone()
	return clone
}

func (enc *jsonEncoder) AddArray(key string, arr zapcore.ArrayMarshaler) error {
	return enc.zapjsonEncoder.AddArray(key, arr)
}

func (enc *jsonEncoder) AddObject(key string, obj zapcore.ObjectMarshaler) error {
	return enc.zapjsonEncoder.AddObject(key, obj)
}

func (enc *jsonEncoder) AddBinary(key string, val []byte) {
	enc.zapjsonEncoder.AddBinary(key, val)
}

func (enc *jsonEncoder) AddByteString(key string, val []byte) {
	enc.zapjsonEncoder.AddByteString(key, val)
}

func (enc *jsonEncoder) AddBool(key string, val bool) {
	enc.zapjsonEncoder.AddBool(key, val)
}

func (enc *jsonEncoder) AddComplex128(key string, val complex128) {
	enc.zapjsonEncoder.AddComplex128(key, val)
}

func (enc *jsonEncoder) AddDuration(key string, val time.Duration) {
	enc.zapjsonEncoder.AddDuration(key, val)
}

func (enc *jsonEncoder) AddFloat64(key string, val float64) {
	enc.zapjsonEncoder.AddFloat64(key, val)
}

func (enc *jsonEncoder) AddInt64(key string, val int64) {
	enc.zapjsonEncoder.AddInt64(key, val)
}

func (enc *jsonEncoder) AddReflected(key string, obj interface{}) error {
	return enc.zapjsonEncoder.AddReflected(key, obj)
}

func (enc *jsonEncoder) OpenNamespace(key string) {
	enc.zapjsonEncoder.OpenNamespace(key)
}

func (enc *jsonEncoder) AddString(key, val string) {
	enc.zapjsonEncoder.AddString(key, val)
}

func (enc *jsonEncoder) AddTime(key string, val time.Time) {
	enc.zapjsonEncoder.AddTime(key, val)
}

func (enc *jsonEncoder) AddUint64(key string, val uint64) {
	enc.zapjsonEncoder.AddUint64(key, val)
}

func (enc *jsonEncoder) AddComplex64(k string, v complex64) { enc.AddComplex128(k, complex128(v)) }
func (enc *jsonEncoder) AddFloat32(k string, v float32)     { enc.AddFloat64(k, float64(v)) }
func (enc *jsonEncoder) AddInt(k string, v int)             { enc.AddInt64(k, int64(v)) }
func (enc *jsonEncoder) AddInt32(k string, v int32)         { enc.AddInt64(k, int64(v)) }
func (enc *jsonEncoder) AddInt16(k string, v int16)         { enc.AddInt64(k, int64(v)) }
func (enc *jsonEncoder) AddInt8(k string, v int8)           { enc.AddInt64(k, int64(v)) }
func (enc *jsonEncoder) AddUint(k string, v uint)           { enc.AddUint64(k, uint64(v)) }
func (enc *jsonEncoder) AddUint32(k string, v uint32)       { enc.AddUint64(k, uint64(v)) }
func (enc *jsonEncoder) AddUint16(k string, v uint16)       { enc.AddUint64(k, uint64(v)) }
func (enc *jsonEncoder) AddUint8(k string, v uint8)         { enc.AddUint64(k, uint64(v)) }
func (enc *jsonEncoder) AddUintptr(k string, v uintptr)     { enc.AddUint64(k, uint64(v)) }

func (enc *jsonEncoder) EncodeEntry(ent zapcore.Entry, fields []zapcore.Field) (*buffer.Buffer, error) {
	return enc.zapjsonEncoder.EncodeEntry(ent, fields)
}

// epochMicrosTimeEncoder takes a time.Time and adds it to the encoder as
// microseconds since Unix epoch.
func epochMicrosTimeEncoder(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
	micros := float64(t.UnixNano()) / float64(time.Microsecond)
	enc.AppendFloat64(micros)
}