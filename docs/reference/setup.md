---
mapped_pages:
  - https://www.elastic.co/guide/en/ecs-logging/go-zap/current/setup.html
navigation_title: Get started
---

# Get started with ECS Logging Go (Zap) [setup]


## Step 1: Install [setup-step-1]

Add the package to your `go.mod` file:

```go
require go.elastic.co/ecszap master
```


## Step 2: Configure [setup-step-2]

Set up a default logger. For example:

```go
encoderConfig := ecszap.NewDefaultEncoderConfig()
core := ecszap.NewCore(encoderConfig, os.Stdout, zap.DebugLevel)
logger := zap.New(core, zap.AddCaller())
```

You can customize your ECS logger. For example:

```go
encoderConfig := ecszap.EncoderConfig{
  EncodeName: customNameEncoder,
  EncodeLevel: zapcore.CapitalLevelEncoder,
  EncodeDuration: zapcore.MillisDurationEncoder,
  EncodeCaller: ecszap.FullCallerEncoder,
}
core := ecszap.NewCore(encoderConfig, os.Stdout, zap.DebugLevel)
logger := zap.New(core, zap.AddCaller())
```


## Examples [examples]


### Use structured logging [use-structured-logging]

```go
// Add fields and a logger name
logger = logger.With(zap.String("custom", "foo"))
logger = logger.Named("mylogger")

// Use strongly typed Field values
logger.Info("some logging info",
    zap.Int("count", 17),
    zap.Error(errors.New("boom")))
```

The example above produces the following log output:

```json
{
  "log.level": "info",
  "@timestamp": "2020-09-13T10:48:03.000Z",
  "log.logger": "mylogger",
  "log.origin": {
    "file.name": "main/main.go",
    "file.line": 265
  },
  "message": "some logging info",
  "ecs.version": "1.6.0",
  "custom": "foo",
  "count": 17,
  "error": {
    "message":"boom"
  }
}
```


### Log errors [log-errors]

```go
err := errors.New("boom")
logger.Error("some error", zap.Error(pkgerrors.Wrap(err, "crash")))
```

The example above produces the following log output:

```json
{
  "log.level": "error",
  "@timestamp": "2020-09-13T10:48:03.000Z",
  "log.logger": "mylogger",
  "log.origin": {
    "file.name": "main/main.go",
    "file.line": 290
  },
  "message": "some error",
  "ecs.version": "1.6.0",
  "custom": "foo",
  "error": {
    "message": "crash: boom",
    "stack_trace": "\nexample.example\n\t/Users/xyz/example/example.go:50\nruntime.example\n\t/Users/xyz/.gvm/versions/go1.13.8.darwin.amd64/src/runtime/proc.go:203\nruntime.goexit\n\t/Users/xyz/.gvm/versions/go1.13.8.darwin.amd64/src/runtime/asm_amd64.s:1357"
  }
}
```


### Use sugar logger [use-sugar-logger]

```go
sugar := logger.Sugar()
sugar.Infow("some logging info",
    "foo", "bar",
    "count", 17,
)
```

The example above produces the following log output:

```json
{
  "log.level": "info",
  "@timestamp": "2020-09-13T10:48:03.000Z",
  "log.logger": "mylogger",
  "log.origin": {
    "file.name": "main/main.go",
    "file.line": 311
  },
  "message": "some logging info",
  "ecs.version": "1.6.0",
  "custom": "foo",
  "foo": "bar",
  "count": 17
}
```


### Wrap a custom underlying `zapcore.Core` [wrap-zapcore]

```go
encoderConfig := ecszap.NewDefaultEncoderConfig()
encoder := zapcore.NewJSONEncoder(encoderConfig.ToZapCoreEncoderConfig())
syslogCore := newSyslogCore(encoder, level) //create your own loggers
core := ecszap.WrapCore(syslogCore)
logger := zap.New(core, zap.AddCaller())
```


### Transition from existing configurations [transition-existing]

Depending on your needs there are different ways to create the logger:

```go
encoderConfig := ecszap.ECSCompatibleEncoderConfig(zap.NewDevelopmentEncoderConfig())
encoder := zapcore.NewJSONEncoder(encoderConfig)
core := zapcore.NewCore(encoder, os.Stdout, zap.DebugLevel)
logger := zap.New(ecszap.WrapCore(core), zap.AddCaller())
```

```go
config := zap.NewProductionConfig()
config.EncoderConfig = ecszap.ECSCompatibleEncoderConfig(config.EncoderConfig)
logger, err := config.Build(ecszap.WrapCoreOption(), zap.AddCaller())
```


## Step 3: Configure Filebeat [setup-step-3]

:::::::{tab-set}

::::::{tab-item} Log file
1. Follow the [Filebeat quick start](beats://docs/reference/filebeat/filebeat-installation-configuration.md)
2. Add the following configuration to your `filebeat.yaml` file.

For Filebeat 7.16+

```yaml
filebeat.inputs:
- type: filestream <1>
  paths: /path/to/logs.json
  parsers:
    - ndjson:
      overwrite_keys: true <2>
      add_error_key: true <3>
      expand_keys: true <4>

processors: <5>
  - add_host_metadata: ~
  - add_cloud_metadata: ~
  - add_docker_metadata: ~
  - add_kubernetes_metadata: ~
```

1. Use the filestream input to read lines from active log files.
2. Values from the decoded JSON object overwrite the fields that {{filebeat}} normally adds (type, source, offset, etc.) in case of conflicts.
3. {{filebeat}} adds an "error.message" and "error.type: json" key in case of JSON unmarshalling errors.
4. {{filebeat}} will recursively de-dot keys in the decoded JSON, and expand them into a hierarchical object structure.
5. Processors enhance your data. See [processors](beats://docs/reference/filebeat/filtering-enhancing-data.md) to learn more.


For Filebeat < 7.16

```yaml
filebeat.inputs:
- type: log
  paths: /path/to/logs.json
  json.keys_under_root: true
  json.overwrite_keys: true
  json.add_error_key: true
  json.expand_keys: true

processors:
- add_host_metadata: ~
- add_cloud_metadata: ~
- add_docker_metadata: ~
- add_kubernetes_metadata: ~
```
::::::

::::::{tab-item} Kubernetes
1. Make sure your application logs to stdout/stderr.
2. Follow the [Run Filebeat on Kubernetes](beats://docs/reference/filebeat/running-on-kubernetes.md) guide.
3. Enable [hints-based autodiscover](beats://docs/reference/filebeat/configuration-autodiscover-hints.md) (uncomment the corresponding section in `filebeat-kubernetes.yaml`).
4. Add these annotations to your pods that log using ECS loggers. This will make sure the logs are parsed appropriately.

```yaml
annotations:
  co.elastic.logs/json.overwrite_keys: true <1>
  co.elastic.logs/json.add_error_key: true <2>
  co.elastic.logs/json.expand_keys: true <3>
```

1. Values from the decoded JSON object overwrite the fields that {{filebeat}} normally adds (type, source, offset, etc.) in case of conflicts.
2. {{filebeat}} adds an "error.message" and "error.type: json" key in case of JSON unmarshalling errors.
3. {{filebeat}} will recursively de-dot keys in the decoded JSON, and expand them into a hierarchical object structure.
::::::

::::::{tab-item} Docker
1. Make sure your application logs to stdout/stderr.
2. Follow the [Run Filebeat on Docker](beats://docs/reference/filebeat/running-on-docker.md) guide.
3. Enable [hints-based autodiscover](beats://docs/reference/filebeat/configuration-autodiscover-hints.md).
4. Add these labels to your containers that log using ECS loggers. This will make sure the logs are parsed appropriately.

```yaml
labels:
  co.elastic.logs/json.overwrite_keys: true <1>
  co.elastic.logs/json.add_error_key: true <2>
  co.elastic.logs/json.expand_keys: true <3>
```

1. Values from the decoded JSON object overwrite the fields that {{filebeat}} normally adds (type, source, offset, etc.) in case of conflicts.
2. {{filebeat}} adds an "error.message" and "error.type: json" key in case of JSON unmarshalling errors.
3. {{filebeat}} will recursively de-dot keys in the decoded JSON, and expand them into a hierarchical object structure.
::::::

:::::::
For more information, see the [Filebeat reference](beats://docs/reference/filebeat/configuring-howto-filebeat.md).

