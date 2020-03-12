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
	"fmt"
	"sync"

	"github.com/pkg/errors"
	"go.uber.org/zap/zapcore"
)

func encodeError(err error, enc zapcore.ObjectEncoder) error {
	enc.AddString("error.message", err.Error())
	if e, ok := err.(stackTracer); ok {
		enc.AddString("error.stacktrace", fmt.Sprintf("%+v", e.StackTrace()))
	}

	// TODO(simi): handle new error
	if e, ok := err.(errorGroup); ok {
		return enc.AddArray("error.cause", errArray(e.Errors()))
	}
	return nil
}

// interface used by github.com/pkg/errors
type stackTracer interface {
	StackTrace() errors.StackTrace
}

// *** code is copied from github.com/zapcore/core.go ***

type errorGroup interface {
	Errors() []error
}

type errArray []error

func (errs errArray) MarshalLogArray(arr zapcore.ArrayEncoder) error {
	for i := range errs {
		if errs[i] == nil {
			continue
		}

		el := newErrArrayElem(errs[i])
		arr.AppendObject(el)
		el.Free()
	}
	return nil
}

var _errArrayElemPool = sync.Pool{New: func() interface{} {
	return &errArrayElem{}
}}

type errArrayElem struct{ err error }

func newErrArrayElem(err error) *errArrayElem {
	e := _errArrayElemPool.Get().(*errArrayElem)
	e.err = err
	return e
}

func (e *errArrayElem) MarshalLogArray(arr zapcore.ArrayEncoder) error {
	return arr.AppendObject(e)
}

func (e *errArrayElem) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	return encodeError(e.err, enc)
}

func (e *errArrayElem) Free() {
	e.err = nil
	_errArrayElemPool.Put(e)
}
