# CHANGELOG
Changelog for ecszap

## unreleased

### Bug Fixes
* Change `stacktrace` to `stack_trace` in output and in json and yaml config option for `EncoderConfig.EnableStacktrace` [pull#21](https://github.com/elastic/ecs-logging-go-zap/pull/21)

## 0.3.0

### Enhancement
* Update ECS version to 1.6.0 [pull#17](https://github.com/elastic/ecs-logging-go-zap/pull/17)

## 0.2.0

### Enhancement
* Add `ecszap.ECSCompatibleEncoderConfig` for making existing encoder config ECS conformant [pull#12](https://github.com/elastic/ecs-logging-go-zap/pull/12)
* Add method `ToZapCoreEncoderConfig` to `ecszap.EncoderConfig` for advanced use cases [pull#12](https://github.com/elastic/ecs-logging-go-zap/pull/12)

### Bug Fixes
* Use `zapcore.ISO8601TimeEncoder` as default instead of `ecszap.EpochMicrosTimeEncoder` [pull#12](https://github.com/elastic/ecs-logging-go-zap/pull/12)

### Breaking Change
* remove `ecszap.NewJSONEncoder` [pull#12](https://github.com/elastic/ecs-logging-go-zap/pull/12)

## 0.1.0
Initial Pre-Release supporting [MVP](https://github.com/elastic/ecs-logging/tree/master/spec#minimum-viable-product) for ECS conformant logging 