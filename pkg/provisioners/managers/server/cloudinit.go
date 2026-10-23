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

package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
)

const (
	// notMultipartContentType asks cloud-init to detect the part's type
	// itself, so we never have to label customer payloads.
	// See the README's "Managed cloud-init augmentation" section.
	notMultipartContentType = "text/x-not-multipart"
	partHandlerContentType  = "text/part-handler"
)

type cloudInitPrefix struct {
	prefix      string
	contentType string
}

// cloudInitPrefixes mirrors cloud-init's INCLUSION_TYPES_MAP
// (cloudinit/handlers/__init__.py), longest prefix first as cloud-init
// matches. It MUST track cloud-init; the cloud-init tests check parity.
func cloudInitPrefixes() []cloudInitPrefix {
	return []cloudInitPrefix{
		{"text/x-shellscript-per-instance", "text/x-shellscript-per-instance"},
		{"text/x-shellscript-per-boot", "text/x-shellscript-per-boot"},
		{"text/x-shellscript-per-once", "text/x-shellscript-per-once"},
		{"#cloud-config-archive", "text/cloud-config-archive"},
		{"#cloud-config-jsonp", "text/cloud-config-jsonp"},
		{"## template: jinja", "text/jinja2"},
		{"#cloud-boothook", "text/cloud-boothook"},
		{"#include-once", "text/x-include-once-url"},
		{"#part-handler", partHandlerContentType},
		{"#cloud-config", "text/cloud-config"},
		{"#include", "text/x-include-url"},
		{"#!", "text/x-shellscript"},
	}
}

// UserDataError reports why a user-data payload was rejected. It unwraps to
// ErrConsistency so provisioner-side error classification is unchanged, while
// boundary callers can recover the caller-facing reason structurally instead
// of parsing the message.
type UserDataError struct {
	Reason string
}

func (e *UserDataError) Error() string {
	return coreerrors.ErrConsistency.Error() + ": " + e.Reason
}

func (e *UserDataError) Unwrap() error {
	return coreerrors.ErrConsistency
}

func userDataError(reason string) error {
	return &UserDataError{Reason: reason}
}

type cloudInitPart struct {
	ContentType string
	FileName    string
	Content     []byte
}

type userDataPart struct {
	header textproto.MIMEHeader
	body   []byte
}

// mergeCloudInitParts appends managed parts after the customer's user-data.
// Customer part bodies MUST reach cloud-init byte for byte, and their
// headers with the same values.
func mergeCloudInitParts(userData []byte, managedParts ...cloudInitPart) ([]byte, error) {
	if len(managedParts) == 0 {
		return append([]byte(nil), userData...), nil
	}

	parts, err := userDataParts(userData)
	if err != nil {
		return nil, err
	}

	for _, part := range managedParts {
		header := textproto.MIMEHeader{"Content-Type": []string{part.ContentType}}
		header.Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, part.FileName))

		parts = append(parts, userDataPart{
			header: header,
			body:   part.Content,
		})
	}

	return marshalMultipartUserData(parts)
}

var (
	errGzip        = userDataError("gzip userData cannot be combined with managed cloud-init augmentation")
	errPartHandler = userDataError("part-handler userData is not supported")
)

func userDataParts(userData []byte) ([]userDataPart, error) {
	if len(userData) == 0 {
		return nil, nil
	}

	if isGzipUserData(userData) {
		return nil, errGzip
	}

	isMIME, payload := mimeUserData(userData)
	if isMIME {
		// Stored user-data the API would now reject is wrapped whole instead,
		// so the server still reconciles.
		if parts, err := parseMIMEUserData(userData); err == nil {
			return parts, nil
		}
	}

	// MUST be encoded, binary, to survive cloud-init byte for byte. See the
	// README's "Managed cloud-init augmentation" section.
	var body bytes.Buffer

	writer := quotedprintable.NewWriter(&body)
	writer.Binary = true

	if _, err := writer.Write(payload); err != nil {
		return nil, fmt.Errorf("%w: unable to encode userData", coreerrors.ErrConsistency)
	}

	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("%w: unable to encode userData", coreerrors.ErrConsistency)
	}

	header := textproto.MIMEHeader{"Content-Type": []string{notMultipartContentType}}
	header.Set("Content-Transfer-Encoding", "quoted-printable")

	return []userDataPart{{header: header, body: body.Bytes()}}, nil
}

// mimeUserData reads user-data as cloud-init does: convert_string, then
// Python's email parser. It is MIME only if it mentions MIME-Version and its
// first line is a header. Otherwise payload is the body cloud-init sniffs:
// all of it, less a blank first line, which the parser takes as the end of
// no headers.
func mimeUserData(userData []byte) (bool, []byte) {
	if !mentionsMIMEVersion(userData) {
		return false, userData
	}

	if startsWithHeader(userData) {
		return true, userData
	}

	if line, rest, ok := bytes.Cut(userData, []byte{'\n'}); ok && len(bytes.TrimSuffix(line, []byte{'\r'})) == 0 {
		return false, rest
	}

	return false, userData
}

// mentionsMIMEVersion matches cloud-init's convert_string: "mime-version:"
// (ASCII case-insensitive) in the first 4096 bytes.
func mentionsMIMEVersion(userData []byte) bool {
	head := bytes.Clone(userData[:min(len(userData), 4096)])

	for i, c := range head {
		if 'A' <= c && c <= 'Z' {
			head[i] = c + 'a' - 'A'
		}
	}

	return bytes.Contains(head, []byte("mime-version:"))
}

// startsWithHeader matches Python's email feedparser headerRE on the first
// line: "From ", a leading space or tab, or printable ASCII up to a colon.
func startsWithHeader(userData []byte) bool {
	line, _, _ := bytes.Cut(userData, []byte{'\n'})

	if bytes.HasPrefix(line, []byte("From ")) || bytes.HasPrefix(line, []byte(" ")) || bytes.HasPrefix(line, []byte("\t")) {
		return true
	}

	name, _, ok := bytes.Cut(line, []byte{':'})
	if !ok {
		return false
	}

	for _, c := range name {
		if c < 0x21 || c > 0x7e {
			return false
		}
	}

	return true
}

// parseMIMEUserData splits a MIME payload into raw top-level parts; a message
// that is not multipart is one part. Raw, not decoded: decoding
// quoted-printable would rewrite the customer's bytes.
func parseMIMEUserData(userData []byte) ([]userDataPart, error) {
	message, err := mail.ReadMessage(bytes.NewReader(userData))
	if err != nil {
		return nil, userDataError("unable to parse MIME userData")
	}

	header := textproto.MIMEHeader(message.Header)

	if !strings.HasPrefix(declaredContentType(header), "multipart/") {
		body, err := io.ReadAll(message.Body)
		if err != nil {
			return nil, userDataError("unable to read MIME userData")
		}

		return []userDataPart{{header: header, body: body}}, nil
	}

	_, params, _ := mime.ParseMediaType(header.Get("Content-Type"))

	boundary := params["boundary"]
	if boundary == "" {
		return nil, userDataError("multipart userData boundary missing")
	}

	reader := multipart.NewReader(message.Body, boundary)
	parts := []userDataPart{}

	for {
		part, err := reader.NextRawPart()
		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			return nil, userDataError("unable to parse multipart userData part")
		}

		body, err := io.ReadAll(part)
		if err != nil {
			return nil, userDataError("unable to read multipart userData part")
		}

		parts = append(parts, userDataPart{
			header: part.Header,
			body:   body,
		})
	}

	return parts, nil
}

func isGzipUserData(userData []byte) bool {
	return bytes.HasPrefix(userData, []byte{0x1f, 0x8b})
}

// isPythonSpace matches Python's str.isspace, which cloud-init's lstrip uses.
func isPythonSpace(r rune) bool {
	return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f)
}

// pythonLower lowers the start of s, at least n bytes of output, as Python's
// str.lower does: unicode.ToLower, except U+0130 becomes two runes. So
// U+212A (Kelvin) lowers to "k", and U+0130 never lowers to "i".
func pythonLower(s []byte, n int) string {
	var b strings.Builder

	for len(s) > 0 && b.Len() < n {
		r, size := utf8.DecodeRune(s)
		s = s[size:]

		if r == '\u0130' {
			b.WriteString("i\u0307")

			continue
		}

		b.WriteRune(unicode.ToLower(r))
	}

	return b.String()
}

// detectContentType returns the type cloud-init's type_from_starts_with
// would give the payload, or "" where it would give none. The payload MUST
// be UTF-8.
func detectContentType(userData []byte) string {
	// 64 bytes is longer than any prefix.
	payload := pythonLower(bytes.TrimLeftFunc(userData, isPythonSpace), 64)

	for _, p := range cloudInitPrefixes() {
		if strings.HasPrefix(payload, p.prefix) {
			return p.contentType
		}
	}

	return ""
}

// validateUserData checks a non-gzip payload is one cloud-init will handle.
// #part-handler is rejected where used openly: as the payload or a top-level
// part. See the README's "Managed cloud-init augmentation" section.
func validateUserData(userData []byte) error {
	// cloud-init's handlers cannot use text that is not UTF-8.
	if !utf8.Valid(userData) {
		return userDataError("userData must be UTF-8")
	}

	isMIME, payload := mimeUserData(userData)
	if !isMIME {
		switch detectContentType(payload) {
		case "":
			return userDataError("unsupported userData format: it must start with a cloud-init marker (e.g. #cloud-config, #!) or be MIME with a MIME-Version header")
		case partHandlerContentType:
			return errPartHandler
		}

		return nil
	}

	parts, err := parseMIMEUserData(userData)
	if err != nil {
		return err
	}

	for _, part := range parts {
		if partContentType(part) == partHandlerContentType {
			return errPartHandler
		}
	}

	return nil
}

// declaredContentType reads a Content-Type as Python's email get_content_type
// does, defaulting to text/plain.
func declaredContentType(header textproto.MIMEHeader) string {
	mediaType, _, _ := strings.Cut(header.Get("Content-Type"), ";")
	mediaType = strings.ToLower(strings.TrimSpace(mediaType))

	if strings.Count(mediaType, "/") != 1 {
		return "text/plain"
	}

	return mediaType
}

// partContentType returns the type cloud-init gives a top-level part: its
// declared type, sniffed from the body only for the types cloud-init sniffs.
func partContentType(part userDataPart) string {
	mediaType := declaredContentType(part.header)

	switch mediaType {
	case "text/plain", notMultipartContentType, "text/x-shellscript":
		if contentType := detectContentType(part.body); contentType != "" {
			return contentType
		}
	}

	return mediaType
}

// ValidateManagedUserData checks that user-data can be safely combined with managed cloud-init augmentation.
func ValidateManagedUserData(userData []byte) error {
	if len(userData) == 0 {
		return nil
	}

	if isGzipUserData(userData) {
		return errGzip
	}

	return validateUserData(userData)
}

// ValidateUserData checks that user-data is a payload this provisioner will accept.
// Unlike ValidateManagedUserData, gzip payloads are permitted: without managed
// augmentation user-data is passed to the platform unmodified, so compressed
// payloads remain valid.
func ValidateUserData(userData []byte) error {
	if len(userData) == 0 || isGzipUserData(userData) {
		return nil
	}

	return validateUserData(userData)
}

func marshalMultipartUserData(parts []userDataPart) ([]byte, error) {
	var body bytes.Buffer

	writer := multipart.NewWriter(&body)
	boundary := multipartUserDataBoundary(parts)

	if err := writer.SetBoundary(boundary); err != nil {
		return nil, fmt.Errorf("%w: unable to set multipart userData boundary", coreerrors.ErrConsistency)
	}

	for _, part := range parts {
		nextPart, err := writer.CreatePart(part.header)
		if err != nil {
			return nil, fmt.Errorf("%w: unable to create multipart userData part", coreerrors.ErrConsistency)
		}

		if _, err := nextPart.Write(part.body); err != nil {
			return nil, fmt.Errorf("%w: unable to write multipart userData part", coreerrors.ErrConsistency)
		}
	}

	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("%w: unable to finalize multipart userData", coreerrors.ErrConsistency)
	}

	var out bytes.Buffer

	if _, err := fmt.Fprintf(&out, "Content-Type: multipart/mixed; boundary=%q\r\nMIME-Version: 1.0\r\n\r\n", writer.Boundary()); err != nil {
		return nil, fmt.Errorf("%w: unable to write multipart userData headers", coreerrors.ErrConsistency)
	}

	if _, err := out.Write(body.Bytes()); err != nil {
		return nil, fmt.Errorf("%w: unable to write multipart userData body", coreerrors.ErrConsistency)
	}

	return out.Bytes(), nil
}

func multipartUserDataBoundary(parts []userDataPart) string {
	seed := sha256.New()

	for _, part := range parts {
		keys := make([]string, 0, len(part.header))
		for key := range part.header {
			keys = append(keys, key)
		}

		sort.Strings(keys)

		for _, key := range keys {
			values := part.header[key]
			_, _ = fmt.Fprintf(seed, "%s:%s\n", key, strings.Join(values, ","))
		}

		_, _ = fmt.Fprintf(seed, "%d\n", len(part.body))
		_, _ = seed.Write(part.body)
	}

	for attempt := 0; ; attempt++ {
		candidateHash := sha256.New()
		_, _ = candidateHash.Write(seed.Sum(nil))
		_, _ = fmt.Fprintf(candidateHash, "%d", attempt)
		boundary := "unikorn-" + hex.EncodeToString(candidateHash.Sum(nil))[:62]

		if !multipartBoundaryOccursInParts(boundary, parts) {
			return boundary
		}
	}
}

func multipartBoundaryOccursInParts(boundary string, parts []userDataPart) bool {
	needle := []byte("--" + boundary)

	for _, part := range parts {
		if bytes.Contains(part.body, needle) {
			return true
		}
	}

	return false
}
