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

var (
	defaultLineEnding     = zapcore.DefaultLineEnding
	defaultEncodeName     = zapcore.FullNameEncoder
	defaultEncodeDuration = zapcore.NanosDurationEncoder
	defaultEncodeLevel    = zapcore.LowercaseLevelEncoder
	defaultEncodeCaller   = ShortCallerEncoder

	messageKey  = "message"
	loglevelKey = "log.level"
	timeKey     = "@timestamp"
	timeEncoder = EpochMicrosTimeEncoder
)

// EncoderConfig exports all non ECS related configurable settings.
// The configuration can be used to create an ECS compatible zapcore.Core
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

	// LineEnding defines the string used for line endings.
	LineEnding string `json:"lineEnding" yaml:"lineEnding"`

	// EncodeName defines how to encode a loggers name.
	// It will only be applied if EnableName is set to true.
	EncodeName zapcore.NameEncoder `json:"nameEncoder" yaml:"nameEncoder"`

	// EncodeLevel sets the log level for which any context should be logged.
	EncodeLevel zapcore.LevelEncoder `json:"levelEncoder" yaml:"levelEncoder"`

	// EncodeDuration sets the format for encoding time.Duration values.
	EncodeDuration zapcore.DurationEncoder `json:"durationEncoder" yaml:"durationEncoder"`

	// EncodeCaller defines how an entry caller should be serialized.
	// It will only be applied if EnableCaller is set to true.
	EncodeCaller CallerEncoder `json:"callerEncoder" yaml:"callerEncoder"`
}

// NewDefaultEncoderConfig returns an EncoderConfig with default settings.
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

// ECSCompatibleEncoderConfig takes an existing zapcore.EncoderConfig
// and sets ECS relevant configuration options to ECS conformant values.
// The returned zapcore.EncoderConfig can be used to create
// an ECS conformant encoder.
// Be aware that this will always replace any set EncodeCaller function
// with the ecszap.ShortCallerEncoder.
// This is a pure convenience function for making a transition from
// existing an zap logger to an ECS conformant zap loggers easier.
// It is recommended to make use of the ecszap.EncoderConfig whenever possible.
func ECSCompatibleEncoderConfig(cfg zapcore.EncoderConfig) zapcore.EncoderConfig {
	cfg.MessageKey = messageKey
	cfg.LevelKey = loglevelKey
	cfg.TimeKey = timeKey
	cfg.EncodeTime = timeEncoder
	if cfg.EncodeDuration == nil {
		cfg.EncodeDuration = zapcore.NanosDurationEncoder
	}
	if cfg.NameKey != "" {
		cfg.NameKey = "log.logger"
	}
	if cfg.StacktraceKey != "" {
		cfg.StacktraceKey = "log.origin.stacktrace"
	}
	if cfg.CallerKey != "" {
		cfg.CallerKey = "log.origin"
		cfg.EncodeCaller = defaultEncodeCaller
	}
	if cfg.EncodeLevel == nil {
		cfg.EncodeLevel = defaultEncodeLevel
	}
	return cfg
}

func toZapCoreEncoderConfig(cfg EncoderConfig) zapcore.EncoderConfig {
	encCfg := zapcore.EncoderConfig{
		MessageKey:     messageKey,
		LevelKey:       loglevelKey,
		TimeKey:        timeKey,
		EncodeTime:     timeEncoder,
		LineEnding:     cfg.LineEnding,
		EncodeDuration: cfg.EncodeDuration,
		EncodeName:     cfg.EncodeName,
		EncodeLevel:    cfg.EncodeLevel,
	}
	if encCfg.EncodeDuration == nil {
		cfg.EncodeDuration = defaultEncodeDuration
	}
	if cfg.EnableName {
		encCfg.NameKey = "log.logger"
		if encCfg.EncodeName == nil {
			cfg.EncodeName = defaultEncodeName
		}
	}
	if cfg.EnableStacktrace {
		encCfg.StacktraceKey = "log.origin.stacktrace"
	}
	if cfg.EnableCaller {
		encCfg.CallerKey = "log.origin"
		if encCfg.EncodeCaller == nil {
			encCfg.EncodeCaller = defaultEncodeCaller
		} else {
			encCfg.EncodeCaller = zapcore.CallerEncoder(cfg.EncodeCaller)
		}
	}
	if encCfg.EncodeLevel == nil {
		encCfg.EncodeLevel = defaultEncodeLevel
	}
	return encCfg
}
