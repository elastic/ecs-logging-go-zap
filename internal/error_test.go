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

package internal

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	errs "github.com/pkg/errors"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type everythingErr struct {
	multiErr
}

func (e everythingErr) StackTrace() errs.StackTrace {
	return errs.StackTrace{}
}

type multiErr struct {
	error
	errors []error
}

func newMultiErr(e ...error) multiErr {
	if len(e) == 0 {
		return multiErr{}
	}
	return multiErr{e[0], e}
}

func (e multiErr) Errors() []error {
	return e.errors
}

func TestEncodeError(t *testing.T) {
	err1 := errors.New("first")
	err2 := errors.New("second")
	stErr := everythingErr{multiErr{error: errors.New("with stacktrace")}}

	for _, tc := range []struct {
		name     string
		err      error
		expected map[string]interface{}
	}{
		{name: "simple", err: err1, expected: map[string]interface{}{"message": "first"}},
		{name: "stacktrace", err: stErr,
			expected: map[string]interface{}{"message": "with stacktrace", "stacktrace": ""}},
		{name: "multi", err: newMultiErr(err1, err2),
			expected: map[string]interface{}{
				"message": "first",
				"cause": []interface{}{
					map[string]interface{}{"message": "first"},
					map[string]interface{}{"message": "second"}}}},
		{name: "multiWithStacktraceCause", err: newMultiErr(err1, newMultiErr(err2, stErr)),
			expected: map[string]interface{}{
				"message": "first",
				"cause": []interface{}{
					map[string]interface{}{"message": "first"},
					map[string]interface{}{
						"message": "second",
						"cause": []interface{}{
							map[string]interface{}{"message": "second"},
							map[string]interface{}{"message": "with stacktrace", "stacktrace": ""},
						},
					},
				},
			}},
		{name: "everything", err: everythingErr{multiErr{errors.New("with stacktrace"), []error{err1, err2}}},
			expected: map[string]interface{}{
				"message": "with stacktrace",
				"cause": []interface{}{
					map[string]interface{}{"message": "first"},
					map[string]interface{}{"message": "second"}},
				"stacktrace": ""}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			enc := zapcore.NewMapObjectEncoder()
			f := zap.Any("err", ecsError{tc.err})
			f.AddTo(enc)
			loggedErr, ok := enc.Fields["err"].(map[string]interface{})
			require.True(t, ok)
			require.Equal(t, len(tc.expected), len(loggedErr))
			for k, v := range tc.expected {
				require.Contains(t, loggedErr, k)
				assert.Equal(t, v, loggedErr[k], k)
			}
		})

	}
}
