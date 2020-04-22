# Elastic Common Schema (ECS) support for uber-go/zap logger

Use this library for automatically adding a minimal set of ECS fields to your logs, when using [uber-go/zap](https://github.com/uber-go/zap).
 
---

**Please note** that this library is in a **beta** version and backwards-incompatible changes might be introduced in future releases. While we strive to comply to [semver](https://semver.org/), we can not guarantee to avoid breaking changes in minor releases.

---
 
The encoder logs in JSON format, using the default [zapcore/json_encoder](https://github.com/uber-go/zap/blob/master/zapcore/json_encoder.go) internally. 

Following fields will be added by default:
```
{
    "log.level":"info",
    "@timestamp":1583748236254129,
    "message":"some logging info",
    "ecs.version":"1.5.0"
}
```

It also takes care of logging error fields in [ECS error format](https://www.elastic.co/guide/en/ecs/current/ecs-error.html). 

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
	"errors"
	"os"

	pkgerrors "github.com/pkg/errors"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

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
	//{
	//	"log.level":"info",
	//	"@timestamp":1584716847523456,
	//	"log.logger":"mylogger",
	//	"log.origin":{
	//		"file.name":"main/main.go",
	//		"file.line":265
	//	},
	//	"message":"some logging info",
	//	"ecs.version":"1.5.0",
	//	"custom":"foo",
	//	"count":17,
	//	"error":{
	//		"message":"boom"
	//	}
	//}

	// Log a wrapped error
	err := errors.New("boom")
	logger.Error("some error", zap.Error(pkgerrors.Wrap(err, "crash")))
	// Log Output:
	//{
	//	"log.level":"error",
	//	"@timestamp":1584716847523842,
	//	"log.logger":"mylogger",
	//	"log.origin":{
	//		"file.name":"main/main.go",
	//		"file.line":290
	//	},
	//	"message":"some error",
	//	"ecs.version":"1.5.0",
	//	"custom":"foo",
	//	"error":{
	//		"message":"crash: boom",
	//		"stacktrace": "\nexample.example\n\t/Users/xyz/example/example.go:50\nruntime.example\n\t/Users/xyz/.gvm/versions/go1.13.8.darwin.amd64/src/runtime/proc.go:203\nruntime.goexit\n\t/Users/xyz/.gvm/versions/go1.13.8.darwin.amd64/src/runtime/asm_amd64.s:1357"
	//	}
	//}

	// Use sugar logger with key-value pairs
	sugar := logger.Sugar()
	sugar.Infow("some logging info",
		"foo", "bar",
		"count", 17,
	)
	// Log Output:
	//{
	//	"log.level":"info",
	//	"@timestamp":1584716847523941,
	//	"log.logger":"mylogger",
	//	"log.origin":{
	//		"file.name":"main/main.go",
	//		"file.line":311
	//	},
	//	"message":"some logging info",
	//	"ecs.version":"1.5.0",
	//	"custom":"foo",
	//	"foo":"bar",
	//	"count":17
	//}

	// Advanced use case: wrap a custom core with ecszap core
	// create your own non-ECS core using a ecszap JSONEncoder
	encoder := ecszap.NewJSONEncoder(ecszap.NewDefaultEncoderConfig())
	core = zapcore.NewCore(encoder, os.Stdout, zap.DebugLevel)
	// wrap your own core with the ecszap core
	logger = zap.New(ecszap.WrapCore(core), zap.AddCaller())
	defer logger.Sync()
	logger.With(zap.Error(errors.New("wrapCore"))).Error("boom")
	// Log Output:
	//{
	//	"log.level":"error",
	//	"@timestamp":1584716847524082,
	//	"log.origin":{
	//		"file.name":"main/main.go",
	//		"file.line":338
	//	},
	//	"message":"boom",
	//	"ecs.version":"1.5.0",
	//	"error":{
	//		"message":"wrapCore"
	//	}
	//}
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
Create a Pull Request from your own fork. 

Run `mage` to update and format you changes before submitting. 

Add new dependencies to the NOTICE.txt.

## License
This software is licensed under the [Apache 2 license](https://github.com/elastic/ecs-logging-go/zap/blob/master/LICENSE). 