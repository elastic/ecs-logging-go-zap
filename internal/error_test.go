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

package internal_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	errs "github.com/pkg/errors"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"go.elastic.co/ecszap/internal"
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

type objMarshalerErr string

func (e objMarshalerErr) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("message", string(e))
	enc.AddString("code", "42")
	return nil
}

func (e objMarshalerErr) Error() string {
	return string(e)
}

func TestEncodeError(t *testing.T) {
	err1 := errors.New("first")
	err2 := errors.New("second")
	stErr := everythingErr{multiErr{error: errors.New("with stack trace")}}

	for _, tc := range []struct {
		name     string
		err      error
		expected map[string]interface{}
	}{
		{name: "simple", err: err1, expected: map[string]interface{}{"message": "first"}},
		{name: "stack_trace", err: stErr,
			expected: map[string]interface{}{"message": "with stack trace", "stack_trace": ""}},
		{name: "multi", err: newMultiErr(err1, err2),
			expected: map[string]interface{}{
				"message": "first",
				"cause": []interface{}{
					map[string]interface{}{"message": "first"},
					map[string]interface{}{"message": "second"}}}},
		{name: "multiWithStackTraceCause", err: newMultiErr(err1, newMultiErr(err2, stErr)),
			expected: map[string]interface{}{
				"message": "first",
				"cause": []interface{}{
					map[string]interface{}{"message": "first"},
					map[string]interface{}{
						"message": "second",
						"cause": []interface{}{
							map[string]interface{}{"message": "second"},
							map[string]interface{}{"message": "with stack trace", "stack_trace": ""},
						},
					},
				},
			}},
		{name: "everything", err: everythingErr{multiErr{errors.New("with stack trace"), []error{err1, err2}}},
			expected: map[string]interface{}{
				"message": "with stack trace",
				"cause": []interface{}{
					map[string]interface{}{"message": "first"},
					map[string]interface{}{"message": "second"}},
				"stack_trace": ""}},
		{name: "withObjectMarshaler", err: objMarshalerErr("with object marshaler"),
			expected: map[string]interface{}{
				"message": "with object marshaler",
				"code":    "42"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			enc := zapcore.NewMapObjectEncoder()
			f := zap.Any("err", internal.NewError(tc.err))
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
