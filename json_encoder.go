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

import "go.uber.org/zap/zapcore"

type jsonEncoder struct {
	zapcore.Encoder
}

// NewJSONEncoder creates a JSON encoder, populating a minimal
// set of Elastic common schema (ECS) fields.
func NewJSONEncoder(cfg EncoderConfig) zapcore.Encoder {
	enc := jsonEncoder{zapcore.NewJSONEncoder(toZapCoreEncoderConfig(cfg))}
	enc.AddString("ecs.version", version)
	return &enc
}

// Clone wraps the zap.JSONEncoder Clone() method.
func (enc *jsonEncoder) Clone() zapcore.Encoder {
	clone := jsonEncoder{}
	clone.Encoder = enc.Encoder.Clone()
	return &clone
}
