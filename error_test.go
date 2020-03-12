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
	"errors"
	"testing"

	errs "github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type multiErr struct {
	msg    string
	errors []error
}

func (e multiErr) Error() string {
	return e.msg
}
func (e multiErr) Errors() []error {
	return e.errors
}

func TestEncodeError(t *testing.T) {
	simpleErr := errors.New("boom")
	wrappedErr := errs.Wrap(simpleErr, "crash")
	multipleErr := multiErr{msg: "boom/foo", errors: []error{simpleErr, errors.New("foo")}}
	multipleWrappedErr := multiErr{msg: "boom/crash", errors: []error{simpleErr, wrappedErr}}

	for _, tt := range []struct {
		name string
		err  error
		keys []string
	}{
		{name: "simple", err: simpleErr, keys: []string{"error.message"}},
		{name: "wrapped", err: wrappedErr, keys: []string{"error.message", "error.stacktrace"}},
		{name: "multi", err: multipleErr, keys: []string{"error.message", "error.cause"}},
		{name: "multiwrapped", err: multipleWrappedErr,
			keys: []string{"error.message", "error.cause", "error.stacktrace"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			enc := newJSONEncoder(NewDefaultEncoderConfig()).(*jsonEncoder)
			require.NoError(t, encodeError(tt.err, enc))
			for _, k := range tt.keys {
				assert.Contains(t, enc.buf.String(), k)
			}
		})
	}
}
