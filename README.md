# ECS Encoder for uber-go/zap logger

Use this encoder for automatically adding a minimal set of ECS fields to your logs, when using [uber-go/zap](https://github.com/uber-go/zap). The encoder logs in JSON format, using the default [zapcore/json_encoder](https://github.com/uber-go/zap/blob/master/zapcore/json_encoder.go) internally. 

Following fields will be added by default:
```
{
  "log.level":"info",
  "@timestamp":1583748236254129,
  "message":"some logging info",
  "ecs.version":"1.5.0"
}
```

## What is ECS?

Elastic Common Schema (ECS) defines a common set of fields for ingesting data into Elasticsearch.
For more information about ECS, visit the [ECS Reference Documentation](https://www.elastic.co/guide/en/ecs/current/ecs-reference.html).

## Installation
Add the package to your `go.mod` file
```
require github.com/elastic/ecs-logging-go-zap master
```

## Example usage
```
   ecszap "github.com/elastic/ecs-logging-go-zap"

	// Build logger from a configuration where Encoding is set to ECSJSONEncoding
	cfg := zap.NewProductionConfig()
	cfg.Encoding = ecszap.JSONEncoding
	logger, err := cfg.Build()
	if err != nil {
		panic(err)
	}
	defer logger.Sync()

	// Use strongly typed Field values
	logger.Info("some logging info",
		zap.String("foo", "bar"),
		zap.Int("count", 17),
	)

	// OR

	// Use sugar logger with key-value pairs
	sugar := logger.Sugar()
	sugar.Infow("some logging info",
		"foo", "bar",
		"count", 17,
	)
```

Log output:
```
{
    "log.level":"info",
    "@timestamp":1583748867663275,
    "message":"some logging info",
    "ecs.version":"1.5.0",
    "foo":"bar",
    "count":17
}
```

## References
* Introduction to ECS [blog post](https://www.elastic.co/blog/introducing-the-elastic-common-schema).
* Logs UI [blog post](https://www.elastic.co/blog/infrastructure-and-logs-ui-new-ways-for-ops-to-interact-with-elasticsearch).

## Test
```
go test ./...
```

## License
This software is licensed under the [Apache 2 license](https://github.com/elastic/ecs-logging-go/zap/blob/master/LICENSE). 