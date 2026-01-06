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

var ErrInvalidQCOW2 = errors.New("invalid QCOW2 image")

func NewQCOW2Reader(r io.Reader) (io.Reader, error) {
	inner := bufio.NewReader(r)

	bs, err := inner.Peek(4)
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, ErrInvalidQCOW2
		}

		return nil, err
	}

	if bs[0] != 'Q' || bs[1] != 'F' || bs[2] != 'I' || bs[3] != 0xfb {
		return nil, ErrInvalidQCOW2
	}

	return inner, nil
}
