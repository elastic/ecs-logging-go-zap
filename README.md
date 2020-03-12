# Elastic Common Schema (ECS) support for uber-go/zap logger

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
import (
	ecszap "github.com/elastic/ecs-logging-go-zap"
)

func main() {
	// Create logger using an ecszap.Core instance
	cfg := ecszap.NewDefaultEncoderConfig()
	core := ecszap.NewCore(cfg, os.Stdout, zap.DebugLevel)
	logger := zap.New(core, zap.AddCaller())
	defer logger.Sync()

	// Adding fields and a logger name
	logger = logger.With(zap.String("custom", "foo"))
	logger = logger.Named("mylogger")

	// Use strongly typed Field values
	logger.Info("some logging info",
		zap.Int("count", 17),
		zap.Error(errors.New("boom")),
	)
	// Log Output:
	//	{
	//	  "log.level":"info",
	//	  "@timestamp":1584029304244694,
	//	  "message":"some logging info",
	//	  "log.logger":"mylogger",
	//	  "log.origin.file.name":"example/example.go",
	//	  "log.origin.file.line":42,
	//	  "ecs.version":"1.5.0",
	//	  "custom":"foo",
	//	  "count":17,
	//	  "error.message":"boom"
	//	}

	// Log a wrapped error
	err := errors.New("boom")
	logger.Error("some error", zap.Error(errs.Wrap(err, "crash")))
	// Log Output:
	//	{
	//	  "log.level":"error",
	//	  "@timestamp":1584029304244786,
	//	  "message":"some error",
	//	  "log.logger":"mylogger",
	//    "log.origin.file.name":"example/example.go",
	//	  "log.origin.file.line":50,
	//	  "ecs.version":"1.5.0",
	//	  "custom":"foo",
	//	  "error.message":"crash: boom",
	//	  "error.stacktrace": "\nexample.example\n\t/Users/xyz/example/example.go:50\nruntime.example\n\t/Users/xyz/.gvm/versions/go1.13.8.darwin.amd64/src/runtime/proc.go:203\nruntime.goexit\n\t/Users/xyz/.gvm/versions/go1.13.8.darwin.amd64/src/runtime/asm_amd64.s:1357"
	//	}

	// Use sugar logger with key-value pairs
	sugar := logger.Sugar()
	sugar.Infow("some logging info",
		"foo", "bar",
		"count", 17,
	)
	// Log Output:
	//	{
	//	  "log.level":"info",
	//	  "@timestamp":1584029304244835,
	//	  "message":"some logging info",
	//	  "log.logger":"mylogger",
	//	  "log.origin.file.name":"example/example.go",
	//	  "log.origin.file.line":54,
	//	  "ecs.version":"1.5.0",
	//	  "custom":"foo",
	//	  "foo":"bar",
	//	  "count":17
	//	}
}
```


## References
* Introduction to ECS [blog post](https://www.elastic.co/blog/introducing-the-elastic-common-schema).
* Logs UI [blog post](https://www.elastic.co/blog/infrastructure-and-logs-ui-new-ways-for-ops-to-interact-with-elasticsearch).

## Test
```
go test ./...
```

## Contribute
Create a Pull Request from your own fork. Run `mage` to update and format you changes before submitting. 

## License
This software is licensed under the [Apache 2 license](https://github.com/elastic/ecs-logging-go/zap/blob/master/LICENSE). 