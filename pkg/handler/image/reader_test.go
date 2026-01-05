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

package image_test

import (
	"bufio"
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

// This checks that it's OK for us to `Peek(...)“ as much as we need to. The docs for `Peek()` say
//
// > If Peek returns fewer than n bytes, it also returns an error explaining why the read is short.
// > The error is ErrBufferFull if n is larger than b's buffer size.
//
//	https://pkg.go.dev/bufio#Reader.Peek
//
// We create the buffer using bufio.NewReader, which will use the default size (if we used exactly
// what we needed, reads could be much less inefficient). The default size is in
//
//	https://cs.opensource.google/go/go/+/refs/tags/go1.25.5:src/bufio/bufio.go;l=19
//
// but not exported so we can't check it directly. It's currently big enough for our purposes;
// this is an early warning of that changing.
func TestBufioDefaultSize(t *testing.T) {
	t.Parallel()

	underlying := bytes.NewBuffer(make([]byte, 10000))
	buffered := bufio.NewReader(underlying)

	_, err := buffered.Peek(512) // the most we peek, from the MBR validation.
	require.NoError(t, err)
}
