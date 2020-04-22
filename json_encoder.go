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

const version = "1.5.0"

var (
	defaultLineEnding     = zapcore.DefaultLineEnding
	defaultEncodeName     = zapcore.FullNameEncoder
	defaultEncodeLevel    = zapcore.LowercaseLevelEncoder
	defaultEncodeDuration = zapcore.NanosDurationEncoder
	defaultEncodeCaller   = internal.ShortCallerEncoder
)

// EncoderConfig allows customization of None-ECS settings.
type EncoderConfig struct {

	// EnableName controls if a logger's name should be serialized
	// when available. If enabled, the EncodeName configuration is
	// used for serialization.
	EnableName bool `json:"enableName" yaml:"enableName"`

	// EnableStacktrace controls if a stacktrace should be serialized when available.
	EnableStacktrace bool `json:"enableStacktrace" yaml:"enableStacktrace"`

	// EnableCaller controls if the entry caller should be serialized.
	// If enabled, the EncodeCaller configuration is used for serialization.
	EnableCaller bool `json:"enableCaller" yaml:"enableCaller"`

	// LineEnding defines the string used for line endings
	LineEnding string `json:"lineEnding" yaml:"lineEnding"`

	// EncodeName defines how to encode a loggers name;
	// will only be applied if EnableName is set to true
	EncodeName zapcore.NameEncoder `json:"nameEncoder" yaml:"nameEncoder"`

	// EncodeLevel sets the log level for which context should be logged
	EncodeLevel zapcore.LevelEncoder `json:"levelEncoder" yaml:"levelEncoder"`

	// EncodeDuration sets the format for encoding time.Duration values
	EncodeDuration zapcore.DurationEncoder `json:"durationEncoder" yaml:"durationEncoder"`

	// EncodeCaller defines how an entry caller should be serialized;
	// will only be applied if EnableCaller is set to true.
	EncodeCaller internal.CallerEncoder `json:"callerEncoder" yaml:"callerEncoder"`
}

// NewDefaultEncoderConfig returns EncoderConfig with default settings.
func NewDefaultEncoderConfig() EncoderConfig {
	return EncoderConfig{
		EnableName:       true,
		EnableCaller:     true,
		EnableStacktrace: true,
		LineEnding:       defaultLineEnding,
		EncodeName:       defaultEncodeName,
		EncodeLevel:      defaultEncodeLevel,
		EncodeDuration:   defaultEncodeDuration,
		EncodeCaller:     defaultEncodeCaller,
	}
}

func (ec EncoderConfig) convertToZapCoreEncoderConfig() zapcore.EncoderConfig {
	cfg := zapcore.EncoderConfig{
		MessageKey:     "message",
		LevelKey:       "log.level",
		TimeKey:        "@timestamp",
		LineEnding:     ec.LineEnding,
		EncodeTime:     internal.EpochMicrosTimeEncoder,
		EncodeDuration: ec.EncodeDuration,
		EncodeName:     ec.EncodeName,
		EncodeCaller:   zapcore.CallerEncoder(ec.EncodeCaller),
		EncodeLevel:    ec.EncodeLevel,
	}
	if cfg.EncodeDuration == nil {
		ec.EncodeDuration = defaultEncodeDuration
	}
	if ec.EnableName {
		cfg.NameKey = "log.logger"
		if cfg.EncodeName == nil {
			ec.EncodeName = defaultEncodeName
		}
	}
	if ec.EnableStacktrace {
		cfg.StacktraceKey = "log.origin.stacktrace"
	}
	if ec.EnableCaller {
		cfg.CallerKey = "log.origin"
		if cfg.EncodeCaller == nil {
			cfg.EncodeCaller = defaultEncodeCaller
		}
	}
	if cfg.EncodeLevel == nil {
		cfg.EncodeLevel = defaultEncodeLevel
	}
	return cfg
}

type jsonEncoder struct {
	zapcore.Encoder
}

// NewJSONEncoder creates a JSON encoder, populating a minimal set of
// Elastic common schema (ECS) values.
// The ECS JSONEncoder uses zap.JSONEncoder internally.
func NewJSONEncoder(cfg EncoderConfig) zapcore.Encoder {
	enc := jsonEncoder{zapcore.NewJSONEncoder(cfg.convertToZapCoreEncoderConfig())}
	enc.AddString("ecs.version", version)
	return &enc
}

// Clone wraps the zap.JSONEncoder Clone() method.
func (enc *jsonEncoder) Clone() zapcore.Encoder {
	clone := jsonEncoder{}
	clone.Encoder = enc.Encoder.Clone()
	return &clone
}
