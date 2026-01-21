/*
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
	_ "embed"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/region/pkg/handler/image"
)

var (
	//go:embed mbr.bin
	mbr []byte
)

// TestImageValidation tests that on receiving a 206 and a MBR the check passes.
func TestImageValidation(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write(mbr)
	}))

	defer server.Close()

	require.NoError(t, image.ValidateImage(t.Context(), server.URL))
}

// TestImageValidationRangeUnsupported tests that on receiving a 200 and a MBR the check passes.
func TestImageValidationRangeUnsupported(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)

		body := make([]byte, 1024)
		copy(body, mbr)

		_, _ = w.Write(body)
	}))

	defer server.Close()

	require.NoError(t, image.ValidateImage(t.Context(), server.URL))
}

// TestImageValidationCannotDial checks that a non existent server errors.
func TestImageValidationCannotDial(t *testing.T) {
	t.Parallel()

	err := &errors.Error{}
	require.ErrorAs(t, image.ValidateImage(t.Context(), "http://i-do-not-exist.acme.com"), &err)
}

// TestImageValidationWrongStatusCode checks a bad status code is handled.
func TestImageValidationWrongStatusCode(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))

	err := &errors.Error{}
	require.ErrorAs(t, image.ValidateImage(t.Context(), server.URL), &err)
}

// TestImageValidationWrongLength tests that receiving a 206 with the incorrect length fails.
func TestImageValidationWrongLength(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write(mbr[:128])
	}))

	defer server.Close()

	err := &errors.Error{}
	require.ErrorAs(t, image.ValidateImage(t.Context(), server.URL), &err)
}

// TestImageValidationRangeUnsupportedTooSmall tests that receiving a 200 and too little
// data fails.
func TestImageValidationRangeUnsupportedTooSmall(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(mbr[:128])
	}))

	defer server.Close()

	err := &errors.Error{}
	require.ErrorAs(t, image.ValidateImage(t.Context(), server.URL), &err)
}

// TestImageValidationWrongMagic tests that on receiving a 206 with invalid magic fails.
// #shialabeoufmagic
func TestImageValidationWrongMagic(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write(make([]byte, 512))
	}))

	defer server.Close()

	err := &errors.Error{}
	require.ErrorAs(t, image.ValidateImage(t.Context(), server.URL), &err)
}
