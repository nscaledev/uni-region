/*
Copyright 2025 the Unikorn Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package region

import (
	"bufio"
	"errors"
	"io"
)

var ErrInvalidMasterBootRecord = errors.New("invalid master boot record")

type MasterBootRecordReader struct {
	inner io.Reader
}

func NewMasterBootRecordReader(r io.Reader) (*MasterBootRecordReader, error) {
	inner := bufio.NewReader(r)

	// Master Boot Record must be at least 512 bytes.
	bs, err := inner.Peek(512)
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, ErrInvalidMasterBootRecord
		}

		return nil, err
	}

	if bs[510] != 0x55 || bs[511] != 0xAA {
		return nil, ErrInvalidMasterBootRecord
	}

	reader := &MasterBootRecordReader{
		inner: inner,
	}

	return reader, nil
}

func (m *MasterBootRecordReader) Read(p []byte) (int, error) {
	return m.inner.Read(p)
}
