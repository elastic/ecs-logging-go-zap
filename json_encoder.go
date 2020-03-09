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
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const JSONEncoding = "ecsjson"

const version = "1.5.0"

func init() {
	zap.RegisterEncoder(JSONEncoding, func(encoderConfig zapcore.EncoderConfig) (zapcore.Encoder, error) {
		return NewJSONEncoder(encoderConfig), nil
	})
}

type jsonEncoder struct {
	zapcore.Encoder
}

// NewJSONEncoder creates a JSON encoder,
// populating a minimal set of Elastic common schema (ECS) values.
// The ECSJSONEncoder uses zap.JSONEncoder internally.
func NewJSONEncoder(cfg zapcore.EncoderConfig) zapcore.Encoder {
	cfg.MessageKey = "message"
	cfg.LevelKey = "log.level"
	cfg.TimeKey = "@timestamp"
	cfg.EncodeTime = epochMicrosTimeEncoder

	enc := jsonEncoder{zapcore.NewJSONEncoder(cfg)}
	enc.AddString("ecs.version", version)
	return &enc
}

func (enc *jsonEncoder) Clone() zapcore.Encoder {
	clone := &jsonEncoder{}
	clone.Encoder = enc.Encoder.Clone()
	return clone
}

// epochMicrosTimeEncoder takes a time.Time and adds it to the encoder as
// microseconds since Unix epoch.
func epochMicrosTimeEncoder(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
	micros := float64(t.UnixNano()) / float64(time.Microsecond)
	enc.AppendFloat64(micros)
}
