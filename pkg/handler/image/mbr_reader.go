/*
Copyright 2025 the Unikorn Authors.
Copyright 2026 Nscale.

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

package image

import (
	"bufio"
	"errors"
	"io"
)

var ErrInvalidMasterBootRecord = errors.New("invalid master boot record")

func NewMasterBootRecordReader(r io.Reader) (io.Reader, error) {
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

	return inner, nil
}
