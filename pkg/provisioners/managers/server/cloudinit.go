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
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"net/textproto"
	"strings"

	coreerrors "github.com/unikorn-cloud/core/pkg/errors"

	"sigs.k8s.io/yaml"
)

//nolint:tagliatelle // cloud-init field names are snake_case.
type cloudConfig struct {
	WriteFiles []cloudConfigWriteFile `json:"write_files,omitempty"`
	RunCmd     [][]string             `json:"runcmd,omitempty"`
}

type cloudConfigWriteFile struct {
	Path        string `json:"path"`
	Owner       string `json:"owner,omitempty"`
	Permissions string `json:"permissions,omitempty"`
	Content     string `json:"content"`
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

func cloudConfigPart(config *cloudConfig, fileName string) (*cloudInitPart, error) {
	data, err := yaml.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("%w: unable to marshal cloud-config", coreerrors.ErrConsistency)
	}

	return &cloudInitPart{
		ContentType: "text/cloud-config",
		FileName:    fileName,
		Content:     append([]byte("#cloud-config\n"), data...),
	}, nil
}

func mergeCloudInitParts(userData []byte, managedParts ...cloudInitPart) ([]byte, error) {
	if len(managedParts) == 0 {
		return append([]byte(nil), userData...), nil
	}

	if len(userData) == 0 && len(managedParts) == 1 {
		return append([]byte(nil), managedParts[0].Content...), nil
	}

	parts, err := userDataParts(userData)
	if err != nil {
		return nil, err
	}

	for _, part := range managedParts {
		parts = append(parts, userDataPart{
			header: newUserDataPartHeader(part.ContentType, part.FileName),
			body:   part.Content,
		})
	}

	return marshalMultipartUserData(parts)
}

func userDataParts(userData []byte) ([]userDataPart, error) {
	if len(userData) == 0 {
		return nil, nil
	}

	if isMultipartUserData(userData) {
		return parseMultipartUserData(userData)
	}

	contentType, err := userDataContentType(userData)
	if err != nil {
		return nil, err
	}

	return []userDataPart{{
		header: newUserDataPartHeader(contentType, ""),
		body:   append([]byte(nil), userData...),
	}}, nil
}

func isMultipartUserData(userData []byte) bool {
	// Fast path, and the fallback for payloads that declare multipart but have
	// otherwise malformed headers, so those still surface multipart-specific
	// parse errors rather than an unrecognized-format error.
	if strings.HasPrefix(strings.ToLower(firstUserDataLine(userData)), "content-type: multipart/") {
		return true
	}

	// MIME does not mandate header order, so Content-Type need not be the first
	// line (e.g. MIME-Version first); parse the headers to detect those.
	message, err := mail.ReadMessage(bytes.NewReader(userData))
	if err != nil {
		return false
	}

	mediaType, _, err := mime.ParseMediaType(message.Header.Get("Content-Type"))
	if err != nil {
		return false
	}

	return strings.HasPrefix(mediaType, "multipart/")
}

func parseMultipartUserData(userData []byte) ([]userDataPart, error) {
	message, err := mail.ReadMessage(bytes.NewReader(userData))
	if err != nil {
		return nil, userDataError("unable to parse multipart userData")
	}

	mediaType, params, err := mime.ParseMediaType(message.Header.Get("Content-Type"))
	if err != nil {
		return nil, userDataError("unable to parse multipart userData content type")
	}

	if !strings.HasPrefix(mediaType, "multipart/") {
		return nil, userDataError("userData is not multipart")
	}

	boundary, ok := params["boundary"]
	if !ok || boundary == "" {
		return nil, userDataError("multipart userData boundary missing")
	}

	reader := multipart.NewReader(message.Body, boundary)
	parts := []userDataPart{}

	for {
		part, err := reader.NextPart()
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

func userDataContentType(userData []byte) (string, error) {
	if isGzipUserData(userData) {
		return "", userDataError("gzip userData cannot be combined with managed cloud-init augmentation")
	}

	switch firstLine := firstUserDataLine(userData); {
	case strings.HasPrefix(firstLine, "## template: jinja"):
		return "text/jinja", nil
	case strings.HasPrefix(firstLine, "#cloud-config"):
		return "text/cloud-config", nil
	case strings.HasPrefix(firstLine, "#!"):
		return "text/x-shellscript", nil
	case strings.HasPrefix(firstLine, "#cloud-boothook"):
		return "text/cloud-boothook", nil
	case strings.HasPrefix(firstLine, "#cloud-config-archive"):
		return "text/cloud-config-archive", nil
	case strings.HasPrefix(firstLine, "#include"):
		return "text/x-include-url", nil
	case strings.HasPrefix(firstLine, "#part-handler"):
		return "text/part-handler", nil
	default:
		return "", userDataError("unsupported userData format: first line must identify a cloud-init payload (e.g. #cloud-config, #!, or a multipart Content-Type header)")
	}
}

// UserDataContentType identifies the cloud-init content type for supported user-data payloads.
func UserDataContentType(userData []byte) (string, error) {
	return userDataContentType(userData)
}

// ValidateManagedUserData checks that user-data can be safely combined with managed cloud-init augmentation.
func ValidateManagedUserData(userData []byte) error {
	_, err := userDataParts(userData)

	return err
}

// ValidateUserData checks that user-data is a payload this provisioner will accept.
// Unlike ValidateManagedUserData, gzip payloads are permitted: without managed
// augmentation user-data is passed to the platform unmodified, so compressed
// payloads remain valid.
func ValidateUserData(userData []byte) error {
	if isGzipUserData(userData) {
		return nil
	}

	_, err := userDataParts(userData)

	return err
}

func firstUserDataLine(userData []byte) string {
	line, _, _ := bytes.Cut(userData, []byte{'\n'})

	return strings.TrimSpace(string(line))
}

func newUserDataPartHeader(contentType, fileName string) textproto.MIMEHeader {
	header := textproto.MIMEHeader{
		"Content-Type": []string{contentType},
	}

	if fileName != "" {
		header.Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, fileName))
	}

	return header
}

func marshalMultipartUserData(parts []userDataPart) ([]byte, error) {
	var body bytes.Buffer

	writer := multipart.NewWriter(&body)

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
