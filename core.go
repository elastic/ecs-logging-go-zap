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
)

// NewCore creates a zapcore.Core that uses an ECS conform JSON Encoder internally.
// It largely falls back to zapcore.Core functionality,
// but implements dedicated parts required to be aligned with ECS.
func NewCore(cfg EncoderConfig, ws zapcore.WriteSyncer, enab zapcore.LevelEnabler) zapcore.Core {
	return newCore(newJSONEncoder(cfg), ws, enab)
}

type core struct {
	zapcore.Core
	enab zapcore.LevelEnabler
	enc  zapcore.Encoder
	out  zapcore.WriteSyncer
}

func (c *core) With(fields []zapcore.Field) zapcore.Core {
	clone := newCore(c.enc.Clone(), c.out, c.enab)
	addFields(clone.enc, fields)
	return clone
}

func newCore(enc zapcore.Encoder, ws zapcore.WriteSyncer, enab zapcore.LevelEnabler) *core {
	return &core{
		enab: enab,
		enc:  enc,
		out:  ws,
		Core: zapcore.NewCore(enc, ws, enab),
	}
}
