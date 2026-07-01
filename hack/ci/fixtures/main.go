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

// integration-fixtures bootstraps identity test principals and simulated region
// resources for the main integration suite.
//
//nolint:forbidigo // stdout output is intentional for .env generation
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	coreopenapi "github.com/unikorn-cloud/core/pkg/openapi"
	identityids "github.com/unikorn-cloud/identity/pkg/ids"
	identityopenapi "github.com/unikorn-cloud/identity/pkg/openapi"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
)

const (
	fixtureActor = "ci-fixtures"

	defaultFixtureCertDuration = time.Hour
	fixtureCertClockSkew       = 2 * time.Minute
	maxFixtureCertRenewBefore  = 15 * time.Minute

	// Region IDs (the Region CRD name, exposed as the API region ID) are UUIDs
	// like every other ID in the API.
	publicRegion  = "e71f2dd2-0bc9-4601-8f3b-9696a1fa90a7"
	privateRegion = "fae390a7-9af3-43e3-9a63-02baa1a16680"

	internalAPICertificateName = "ci-region-api-tests"
	internalAPISystemAccountCN = "unikorn-compute"
	internalAPICertFilename    = "internal-api-client.crt"
	internalAPIKeyFilename     = "internal-api-client.key"
	internalCertDuration       = time.Hour
)

var (
	errOpenstackTestRegionIDRequired = errors.New("TEST_REGION_ID or --test-region-id must be set when REGION_PROVIDER=openstack")
	errRegionProviderMismatch        = errors.New("region fixture has unexpected provider")
	errUnsupportedRegionProvider     = errors.New("unsupported region provider fixture mode")
)

func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "ERROR: "+format+"\n", args...)
	os.Exit(1)
}

func logf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "==> "+format+"\n", args...)
}

func envOrDefault(name, fallback string) string {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}

	return value
}

func fixtureCertRenewBefore(duration time.Duration) time.Duration {
	renewBefore := duration / 4
	if renewBefore > maxFixtureCertRenewBefore {
		return maxFixtureCertRenewBefore
	}

	return renewBefore
}

func buildCertificate(namespace, name, cn string, duration time.Duration) *unstructured.Unstructured {
	cert := &unstructured.Unstructured{}
	cert.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "cert-manager.io",
		Version: "v1",
		Kind:    "Certificate",
	})
	cert.SetNamespace(namespace)
	cert.SetName(name)
	cert.Object["spec"] = map[string]interface{}{
		"secretName": name + "-tls",
		"commonName": cn,
		"duration":   duration.String(),
		"issuerRef": map[string]interface{}{
			"name":  "unikorn-client-issuer",
			"kind":  "ClusterIssuer",
			"group": "cert-manager.io",
		},
	}

	return cert
}

func ensureCertificate(ctx context.Context, k8s client.Client, cert *unstructured.Unstructured) {
	if err := k8s.Create(ctx, cert); err == nil {
		return
	} else if client.IgnoreAlreadyExists(err) != nil {
		fatalf("failed to create Certificate %s/%s: %v", cert.GetNamespace(), cert.GetName(), err)
	}

	current := &unstructured.Unstructured{}
	current.SetGroupVersionKind(cert.GroupVersionKind())

	key := types.NamespacedName{Namespace: cert.GetNamespace(), Name: cert.GetName()}
	if err := k8s.Get(ctx, key, current); err != nil {
		fatalf("failed to read Certificate %s/%s: %v", key.Namespace, key.Name, err)
	}

	before := current.DeepCopy()
	current.Object["spec"] = cert.Object["spec"]

	if err := k8s.Patch(ctx, current, client.MergeFrom(before)); err != nil {
		fatalf("failed to update Certificate %s/%s: %v", key.Namespace, key.Name, err)
	}
}

func waitForCertificateReady(ctx context.Context, k8s client.Client, cert *unstructured.Unstructured) {
	if err := wait.PollUntilContextTimeout(ctx, 2*time.Second, 60*time.Second, true, func(ctx context.Context) (bool, error) {
		current := &unstructured.Unstructured{}
		current.SetGroupVersionKind(cert.GroupVersionKind())

		if err := k8s.Get(ctx, types.NamespacedName{Namespace: cert.GetNamespace(), Name: cert.GetName()}, current); err != nil {
			return false, nil //nolint:nilerr
		}

		conditions, _, _ := unstructured.NestedSlice(current.Object, "status", "conditions")
		for _, c := range conditions {
			m, ok := c.(map[string]interface{})
			if !ok {
				continue
			}

			if m["type"] == "Ready" && m["status"] == "True" {
				return true, nil
			}
		}

		return false, nil
	}); err != nil {
		fatalf("Certificate %s/%s not ready: %v", cert.GetNamespace(), cert.GetName(), err)
	}
}

type certificateMaterial struct {
	certPEM []byte
	keyPEM  []byte
	cert    *x509.Certificate
}

func readCertificateMaterial(secret *corev1.Secret) (certificateMaterial, string) {
	certPEM, ok := secret.Data["tls.crt"]
	if !ok || len(certPEM) == 0 {
		return certificateMaterial{}, "missing tls.crt"
	}

	keyPEM, ok := secret.Data["tls.key"]
	if !ok || len(keyPEM) == 0 {
		return certificateMaterial{}, "missing tls.key"
	}

	keyPair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return certificateMaterial{}, fmt.Sprintf("invalid key pair: %v", err)
	}

	if len(keyPair.Certificate) == 0 {
		return certificateMaterial{}, "missing leaf certificate"
	}

	cert, err := x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return certificateMaterial{}, fmt.Sprintf("invalid leaf certificate: %v", err)
	}

	return certificateMaterial{certPEM: certPEM, keyPEM: keyPEM, cert: cert}, ""
}

func validateCertificateSecret(secret *corev1.Secret, cn string, duration, renewBefore time.Duration) ([]byte, []byte, string) {
	material, reason := readCertificateMaterial(secret)
	if reason != "" {
		return nil, nil, reason
	}

	if material.cert.Subject.CommonName != cn {
		return nil, nil, fmt.Sprintf("common name %q does not match %q", material.cert.Subject.CommonName, cn)
	}

	lifetime := material.cert.NotAfter.Sub(material.cert.NotBefore)
	if lifetime+fixtureCertClockSkew < duration {
		return nil, nil, fmt.Sprintf("certificate lifetime %s is shorter than requested duration %s", lifetime, duration)
	}

	now := time.Now()
	if now.Add(fixtureCertClockSkew).Before(material.cert.NotBefore) {
		return nil, nil, fmt.Sprintf("certificate is not valid before %s", material.cert.NotBefore.Format(time.RFC3339))
	}

	if now.Add(renewBefore).After(material.cert.NotAfter) {
		return nil, nil, fmt.Sprintf("certificate expires at %s", material.cert.NotAfter.Format(time.RFC3339))
	}

	return material.certPEM, material.keyPEM, ""
}

func readValidCertificateSecret(ctx context.Context, k8s client.Client, key types.NamespacedName, cn string, duration, renewBefore time.Duration) ([]byte, []byte, bool) {
	secret := &corev1.Secret{}
	if err := k8s.Get(ctx, key, secret); err != nil {
		if client.IgnoreNotFound(err) == nil {
			return nil, nil, false
		}

		fatalf("failed to read Secret %s/%s: %v", key.Namespace, key.Name, err)
	}

	certPEM, keyPEM, reason := validateCertificateSecret(secret, cn, duration, renewBefore)
	if reason == "" {
		return certPEM, keyPEM, true
	}

	logf("Existing Secret %s/%s cannot be reused: %s", key.Namespace, key.Name, reason)

	if err := k8s.Delete(ctx, secret); client.IgnoreNotFound(err) != nil {
		fatalf("failed to delete stale Secret %s/%s: %v", key.Namespace, key.Name, err)
	}

	return nil, nil, false
}

func waitForValidCertificateSecret(ctx context.Context, k8s client.Client, key types.NamespacedName, cn string, duration, renewBefore time.Duration) ([]byte, []byte) {
	var (
		certPEM []byte
		keyPEM  []byte
	)

	lastReason := "secret has not been created"

	if err := wait.PollUntilContextTimeout(ctx, 2*time.Second, 60*time.Second, true, func(ctx context.Context) (bool, error) {
		secret := &corev1.Secret{}
		if err := k8s.Get(ctx, key, secret); err != nil {
			if client.IgnoreNotFound(err) == nil {
				lastReason = "secret has not been created"

				return false, nil
			}

			return false, err
		}

		certPEM, keyPEM, lastReason = validateCertificateSecret(secret, cn, duration, renewBefore)

		return lastReason == "", nil
	}); err != nil {
		fatalf("Certificate Secret %s/%s not usable: %s: %v", key.Namespace, key.Name, lastReason, err)
	}

	return certPEM, keyPEM
}

func issueCert(ctx context.Context, k8s client.Client, namespace, name, cn string, duration time.Duration) ([]byte, []byte) {
	secretKey := types.NamespacedName{Namespace: namespace, Name: name + "-tls"}
	renewBefore := fixtureCertRenewBefore(duration)

	if certPEM, keyPEM, ok := readValidCertificateSecret(ctx, k8s, secretKey, cn, duration, renewBefore); ok {
		logf("Reusing mTLS client certificate for %s; it remains valid for at least %s.", cn, renewBefore)

		return certPEM, keyPEM
	}

	cert := buildCertificate(namespace, name, cn, duration)
	ensureCertificate(ctx, k8s, cert)
	waitForCertificateReady(ctx, k8s, cert)

	return waitForValidCertificateSecret(ctx, k8s, secretKey, cn, duration, renewBefore)
}

func newIdentityClient(baseURL, caCertPath string, certPEM, keyPEM []byte) *identityopenapi.ClientWithResponses {
	caBytes, err := os.ReadFile(caCertPath)
	if err != nil {
		fatalf("failed to read CA cert: %v", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caBytes) {
		fatalf("failed to parse CA cert")
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		fatalf("failed to parse mTLS key pair: %v", err)
	}

	principalJSON, err := json.Marshal(map[string]string{"actor": fixtureActor})
	if err != nil {
		fatalf("failed to marshal principal: %v", err)
	}

	principalHeader := base64.RawURLEncoding.EncodeToString(principalJSON)

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:   tls.VersionTLS12,
				Certificates: []tls.Certificate{cert},
				RootCAs:      caPool,
			},
		},
		Timeout: 30 * time.Second,
	}

	principalEditor := func(_ context.Context, req *http.Request) error {
		req.Header.Set("X-Principal", principalHeader)
		return nil
	}

	ac, err := identityopenapi.NewClientWithResponses(baseURL,
		identityopenapi.WithHTTPClient(httpClient),
		identityopenapi.WithRequestEditorFn(principalEditor),
	)
	if err != nil {
		fatalf("failed to create identity API client: %v", err)
	}

	return ac
}

func findRole(roles *identityopenapi.RolesResponse, name string) string {
	if roles == nil {
		return ""
	}

	for _, role := range *roles {
		if role.Metadata.Name == name {
			return role.Metadata.Id
		}
	}

	return ""
}

func waitForOrgNamespace(ctx context.Context, k8s client.Client, namespace, orgID string) {
	if err := wait.PollUntilContextTimeout(ctx, 2*time.Second, 60*time.Second, true, func(ctx context.Context) (bool, error) {
		org := &unstructured.Unstructured{}
		org.SetGroupVersionKind(schema.GroupVersionKind{
			Group:   "identity.unikorn-cloud.org",
			Version: "v1alpha1",
			Kind:    "Organization",
		})

		if err := k8s.Get(ctx, types.NamespacedName{Namespace: namespace, Name: orgID}, org); err != nil {
			return false, nil //nolint:nilerr
		}

		ns, _, _ := unstructured.NestedString(org.Object, "status", "namespace")

		return ns != "", nil
	}); err != nil {
		fatalf("Organization %s not provisioned: %v", orgID, err)
	}
}

func createOrganization(ctx context.Context, ac *identityopenapi.ClientWithResponses, k8s client.Client, identityNamespace, name string) string {
	resp, err := ac.PostApiV1OrganizationsWithResponse(ctx, identityopenapi.OrganizationWrite{
		Metadata: coreopenapi.ResourceWriteMetadata{Name: name},
		Spec:     identityopenapi.OrganizationSpec{OrganizationType: identityopenapi.Adhoc},
	})
	if err != nil {
		fatalf("failed to create Organization %q: %v", name, err)
	}

	if resp.JSON202 == nil {
		fatalf("create Organization %q returned %s", name, resp.Status())
	}

	orgID := resp.JSON202.Metadata.Id
	waitForOrgNamespace(ctx, k8s, identityNamespace, orgID)

	return orgID
}

func resolveRoles(ctx context.Context, ac *identityopenapi.ClientWithResponses, orgID string) (string, string) {
	rolesResp, err := ac.GetApiV1OrganizationsOrganizationIDRolesWithResponse(ctx, identityids.MustParseOrganizationID(orgID))
	if err != nil {
		fatalf("failed to list roles for org %s: %v", orgID, err)
	}

	if rolesResp.JSON200 == nil {
		fatalf("list roles for org %s returned %s", orgID, rolesResp.Status())
	}

	adminRoleID := findRole(rolesResp.JSON200, "administrator")
	userRoleID := findRole(rolesResp.JSON200, "user")

	if adminRoleID == "" || userRoleID == "" {
		fatalf("required roles not found for org %s", orgID)
	}

	return adminRoleID, userRoleID
}

func createGroup(ctx context.Context, ac *identityopenapi.ClientWithResponses, orgID, name string, roleIDs []string) string {
	resp, err := ac.PostApiV1OrganizationsOrganizationIDGroupsWithResponse(ctx, identityids.MustParseOrganizationID(orgID), identityopenapi.GroupWrite{
		Metadata: coreopenapi.ResourceWriteMetadata{Name: name},
		Spec: identityopenapi.GroupSpec{
			RoleIDs:           roleIDs,
			ServiceAccountIDs: identityopenapi.StringList{},
		},
	})
	if err != nil {
		fatalf("failed to create group %q: %v", name, err)
	}

	if resp.JSON201 == nil {
		fatalf("create group %q returned %s", name, resp.Status())
	}

	return resp.JSON201.Metadata.Id
}

func createProject(ctx context.Context, ac *identityopenapi.ClientWithResponses, orgID, name string, groupIDs []string) string {
	resp, err := ac.PostApiV1OrganizationsOrganizationIDProjectsWithResponse(ctx, identityids.MustParseOrganizationID(orgID), identityopenapi.ProjectWrite{
		Metadata: coreopenapi.ResourceWriteMetadata{Name: name},
		Spec:     identityopenapi.ProjectSpec{GroupIDs: groupIDs},
	})
	if err != nil {
		fatalf("failed to create project %q: %v", name, err)
	}

	if resp.JSON202 == nil {
		fatalf("create project %q returned %s", name, resp.Status())
	}

	return resp.JSON202.Metadata.Id
}

func createServiceAccount(ctx context.Context, ac *identityopenapi.ClientWithResponses, orgID, name string, groupIDs []string) (string, string) {
	resp, err := ac.PostApiV1OrganizationsOrganizationIDServiceaccountsWithResponse(ctx, identityids.MustParseOrganizationID(orgID), identityopenapi.ServiceAccountWrite{
		Metadata: coreopenapi.ResourceWriteMetadata{Name: name},
		Spec:     identityopenapi.ServiceAccountSpec{GroupIDs: groupIDs},
	})
	if err != nil {
		fatalf("failed to create service account %q: %v", name, err)
	}

	if resp.JSON201 == nil {
		fatalf("create service account %q returned %s", name, resp.Status())
	}

	token := ""
	if resp.JSON201.Status.AccessToken != nil {
		token = *resp.JSON201.Status.AccessToken
	}

	return resp.JSON201.Metadata.Id, token
}

type primaryFixture struct {
	orgID        string
	projectID    string
	adminGroupID string
	userGroupID  string
	adminSAID    string
	userSAID     string
	adminToken   string
	userToken    string
}

func createPrimaryFixtures(ctx context.Context, ac *identityopenapi.ClientWithResponses, k8s client.Client, identityNamespace string) primaryFixture {
	orgID := createOrganization(ctx, ac, k8s, identityNamespace, "ci-test-org")
	adminRoleID, userRoleID := resolveRoles(ctx, ac, orgID)

	adminGroupID := createGroup(ctx, ac, orgID, "ci-admin-group", []string{adminRoleID})
	userGroupID := createGroup(ctx, ac, orgID, "ci-user-group", []string{userRoleID})
	projectID := createProject(ctx, ac, orgID, "ci-test-project", []string{adminGroupID, userGroupID})
	adminSAID, adminToken := createServiceAccount(ctx, ac, orgID, "ci-admin-sa", []string{adminGroupID})
	userSAID, userToken := createServiceAccount(ctx, ac, orgID, "ci-user-sa", []string{userGroupID})

	return primaryFixture{
		orgID:        orgID,
		projectID:    projectID,
		adminGroupID: adminGroupID,
		userGroupID:  userGroupID,
		adminSAID:    adminSAID,
		userSAID:     userSAID,
		adminToken:   adminToken,
		userToken:    userToken,
	}
}

func createSecondaryFixtures(ctx context.Context, ac *identityopenapi.ClientWithResponses, k8s client.Client, identityNamespace string) (string, string) {
	orgID := createOrganization(ctx, ac, k8s, identityNamespace, "ci-secondary-org")
	adminRoleID, _ := resolveRoles(ctx, ac, orgID)
	adminGroupID := createGroup(ctx, ac, orgID, "ci-secondary-admin-group", []string{adminRoleID})
	_, token := createServiceAccount(ctx, ac, orgID, "ci-secondary-admin-sa", []string{adminGroupID})

	return orgID, token
}

func upsertRegion(ctx context.Context, k8s client.Client, regionNamespace, name string, organizationIDs []string) {
	region := &regionv1.Region{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: regionNamespace,
			Labels: map[string]string{
				coreconstants.NameLabel: name,
			},
		},
		Spec: regionv1.RegionSpec{
			Provider: regionv1.ProviderSimulated,
		},
	}

	if len(organizationIDs) > 0 {
		region.Spec.Security = &regionv1.RegionSecuritySpec{
			Organizations: make([]regionv1.RegionSecurityOrganizationSpec, len(organizationIDs)),
		}

		for i, organizationID := range organizationIDs {
			region.Spec.Security.Organizations[i] = regionv1.RegionSecurityOrganizationSpec{ID: organizationID}
		}
	}

	current := &regionv1.Region{}
	key := types.NamespacedName{Namespace: regionNamespace, Name: name}

	if err := k8s.Get(ctx, key, current); err == nil {
		current.Labels = region.Labels
		current.Spec = region.Spec

		if err := k8s.Update(ctx, current); err != nil {
			fatalf("failed to update region %q: %v", name, err)
		}

		return
	}

	if err := k8s.Create(ctx, region); err != nil {
		fatalf("failed to create region %q: %v", name, err)
	}
}

func getExistingRegion(ctx context.Context, k8s client.Client, regionNamespace, name string) (*regionv1.Region, error) {
	region := &regionv1.Region{}
	key := types.NamespacedName{Namespace: regionNamespace, Name: name}

	if err := k8s.Get(ctx, key, region); err != nil {
		return nil, fmt.Errorf("region fixture %q was not found in namespace %q: %w", name, regionNamespace, err)
	}

	return region, nil
}

func getExistingRegionProvider(ctx context.Context, k8s client.Client, regionNamespace, name string) (regionv1.Provider, error) {
	region, err := getExistingRegion(ctx, k8s, regionNamespace, name)
	if err != nil {
		return "", err
	}

	return region.Spec.Provider, nil
}

func main() {
	opts := parseOptions()
	run(opts)
}

type options struct {
	baseURL                 string
	identityNamespace       string
	regionNamespace         string
	regionBaseURL           string
	caCertPath              string
	regionCACertPath        string
	fixtureCertDuration     time.Duration
	regionProvider          string
	testRegionID            string
	serverFlavorID          string
	serverImageID           string
	serverInfrastructureRef string
	internalCertDir         string
}

type internalAPICredentials struct {
	certPath string
	keyPath  string
	cn       string
}

func parseOptions() options {
	baseURL := flag.String("base-url", os.Getenv("IDENTITY_BASE_URL"), "Identity service base URL")
	identityNamespace := flag.String("identity-namespace", os.Getenv("IDENTITY_NAMESPACE"), "Identity Kubernetes namespace")
	regionNamespace := flag.String("region-namespace", os.Getenv("REGION_NAMESPACE"), "Region Kubernetes namespace")
	regionBaseURL := flag.String("region-base-url", os.Getenv("REGION_BASE_URL"), "Region service base URL")
	caCertPath := flag.String("ca-cert", os.Getenv("IDENTITY_CA_CERT"), "Path to CA certificate bundle")
	regionCACertPath := flag.String("region-ca-cert", os.Getenv("REGION_CA_CERT"), "Path to region CA certificate bundle")
	fixtureCertDuration := flag.String("fixture-cert-duration", envOrDefault("FIXTURE_CERT_DURATION", defaultFixtureCertDuration.String()), "Duration for generated mTLS fixture certificates")
	regionProvider := flag.String("region-provider", os.Getenv("REGION_PROVIDER"), "Expected region provider fixture mode: simulated or openstack")
	testRegionID := flag.String("test-region-id", firstEnv("TEST_REGION_ID", "OPENSTACK_REGION_ID"), "Existing region ID to use for tests; provider is inferred from the Region CR when set")
	serverFlavorID := flag.String("server-flavor-id", firstEnv("TEST_SERVER_FLAVOR_ID", "UNIKORN_OPENSTACK_FLAVOR_ID"), "Flavor ID used by OpenStack server lifecycle tests")
	serverImageID := flag.String("server-image-id", firstEnv("TEST_SERVER_IMAGE_ID", "UNIKORN_OPENSTACK_IMAGE_ID"), "Image ID used by OpenStack server lifecycle tests")
	serverInfrastructureRef := flag.String("server-infrastructure-ref", firstEnv("TEST_SERVER_INFRASTRUCTURE_REF", "UNIKORN_OPENSTACK_INFRASTRUCTURE_REF"), "Provider-specific infrastructure reference used by server placement tests")
	internalCertDir := flag.String("internal-cert-dir", os.Getenv("INTERNAL_API_CERT_DIR"), "Directory for generated internal API client certificate files")
	flag.Parse()

	if *baseURL == "" || *identityNamespace == "" || *regionNamespace == "" || *regionBaseURL == "" || *caCertPath == "" {
		fmt.Fprintln(os.Stderr, `Usage: fixtures --base-url URL --identity-namespace NS
			--region-namespace NS --region-base-url URL --ca-cert PATH
			[--region-ca-cert PATH] [--fixture-cert-duration DURATION]
			[--internal-cert-dir DIR]
			[--server-flavor-id ID] [--server-image-id ID]
			[--server-infrastructure-ref REF]
			[--region-provider simulated|openstack] [--test-region-id ID]`)
		os.Exit(1)
	}

	duration, err := time.ParseDuration(*fixtureCertDuration)
	if err != nil {
		fatalf("invalid --fixture-cert-duration %q: %v", *fixtureCertDuration, err)
	}

	if duration <= 0 {
		fatalf("--fixture-cert-duration must be positive")
	}

	internalCertDirValue := *internalCertDir
	if internalCertDirValue == "" {
		internalCertDirValue = "test"
	}

	return options{
		baseURL:                 *baseURL,
		identityNamespace:       *identityNamespace,
		regionNamespace:         *regionNamespace,
		regionBaseURL:           *regionBaseURL,
		caCertPath:              *caCertPath,
		regionCACertPath:        *regionCACertPath,
		fixtureCertDuration:     duration,
		regionProvider:          *regionProvider,
		testRegionID:            *testRegionID,
		serverFlavorID:          *serverFlavorID,
		serverImageID:           *serverImageID,
		serverInfrastructureRef: *serverInfrastructureRef,
		internalCertDir:         internalCertDirValue,
	}
}

func firstEnv(names ...string) string {
	for _, name := range names {
		if value := os.Getenv(name); value != "" {
			return value
		}
	}

	return ""
}

func validateSupportedProvider(provider regionv1.Provider) error {
	switch provider {
	case regionv1.ProviderSimulated, regionv1.ProviderOpenstack:
		return nil
	case regionv1.ProviderKubernetes:
		return fmt.Errorf("%w %q", errUnsupportedRegionProvider, provider)
	default:
		return fmt.Errorf("%w %q", errUnsupportedRegionProvider, provider)
	}
}

func resolveRegionFixture(ctx context.Context, k8s client.Client, regionNamespace, expectedProvider, explicitRegionID string) (regionv1.Provider, string, bool, error) {
	if expectedProvider != "" {
		provider := regionv1.Provider(expectedProvider)
		if err := validateSupportedProvider(provider); err != nil {
			return "", "", false, err
		}
	}

	if explicitRegionID == "" {
		if regionv1.Provider(expectedProvider) == regionv1.ProviderOpenstack {
			return "", "", false, errOpenstackTestRegionIDRequired
		}

		return regionv1.ProviderSimulated, publicRegion, false, nil
	}

	provider, err := getExistingRegionProvider(ctx, k8s, regionNamespace, explicitRegionID)
	if err != nil {
		return "", "", false, err
	}

	if err := validateSupportedProvider(provider); err != nil {
		return "", "", false, err
	}

	if expectedProvider != "" && provider != regionv1.Provider(expectedProvider) {
		return "", "", false, fmt.Errorf("%w: %q in namespace %q has provider %q, want %q", errRegionProviderMismatch, explicitRegionID, regionNamespace, provider, expectedProvider)
	}

	return provider, explicitRegionID, true, nil
}

func resolveCertPaths(opts options) options {
	absCACertPath, err := filepath.Abs(opts.caCertPath)
	if err != nil {
		fatalf("failed to resolve CA cert path: %v", err)
	}

	opts.caCertPath = absCACertPath

	if opts.regionCACertPath == "" {
		opts.regionCACertPath = opts.caCertPath
	}

	absRegionCACertPath, err := filepath.Abs(opts.regionCACertPath)
	if err != nil {
		fatalf("failed to resolve region CA cert path: %v", err)
	}

	opts.regionCACertPath = absRegionCACertPath

	absInternalCertDir, err := filepath.Abs(opts.internalCertDir)
	if err != nil {
		fatalf("failed to resolve internal API cert dir: %v", err)
	}

	opts.internalCertDir = absInternalCertDir

	return opts
}

func newKubernetesClient() client.Client {
	scheme := runtime.NewScheme()

	if err := corev1.AddToScheme(scheme); err != nil {
		fatalf("failed to register core scheme: %v", err)
	}

	if err := regionv1.AddToScheme(scheme); err != nil {
		fatalf("failed to register region scheme: %v", err)
	}

	cfg, err := config.GetConfig()
	if err != nil {
		fatalf("failed to get kubeconfig: %v", err)
	}

	k8s, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		fatalf("failed to create Kubernetes client: %v", err)
	}

	return k8s
}

func writeInternalAPICredentials(opts options, certPEM, keyPEM []byte) internalAPICredentials {
	if err := os.MkdirAll(opts.internalCertDir, 0700); err != nil {
		fatalf("failed to create internal API cert dir: %v", err)
	}

	certPath := filepath.Join(opts.internalCertDir, internalAPICertFilename)
	keyPath := filepath.Join(opts.internalCertDir, internalAPIKeyFilename)

	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		fatalf("failed to write internal API client certificate: %v", err)
	}

	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		fatalf("failed to write internal API client key: %v", err)
	}

	return internalAPICredentials{
		certPath: certPath,
		keyPath:  keyPath,
		cn:       internalAPISystemAccountCN,
	}
}

func emitEnv(opts options, primary primaryFixture, secondaryOrgID, secondaryToken string, testRegionID string, internalAPI internalAPICredentials) {
	fmt.Printf("API_BASE_URL=%s\n", opts.regionBaseURL)
	fmt.Printf("REGION_BASE_URL=%s\n", opts.regionBaseURL)
	fmt.Printf("REGION_CA_CERT=%s\n", opts.regionCACertPath)
	fmt.Printf("IDENTITY_BASE_URL=%s\n", opts.baseURL)
	fmt.Printf("IDENTITY_CA_CERT=%s\n", opts.caCertPath)
	fmt.Printf("TEST_ORG_ID=%s\n", primary.orgID)
	fmt.Printf("TEST_PROJECT_ID=%s\n", primary.projectID)
	fmt.Printf("API_AUTH_TOKEN=%s\n", primary.adminToken)
	fmt.Printf("TEST_ADMIN_GROUP_ID=%s\n", primary.adminGroupID)
	fmt.Printf("TEST_USER_GROUP_ID=%s\n", primary.userGroupID)
	fmt.Printf("TEST_ADMIN_SA_ID=%s\n", primary.adminSAID)
	fmt.Printf("TEST_USER_SA_ID=%s\n", primary.userSAID)
	fmt.Printf("ADMIN_AUTH_TOKEN=%s\n", primary.adminToken)
	fmt.Printf("USER_AUTH_TOKEN=%s\n", primary.userToken)
	fmt.Printf("TEST_REGION_ID=%s\n", testRegionID)
	fmt.Printf("TEST_SERVER_FLAVOR_ID=%s\n", opts.serverFlavorID)
	fmt.Printf("TEST_SERVER_IMAGE_ID=%s\n", opts.serverImageID)
	fmt.Printf("TEST_SERVER_INFRASTRUCTURE_REF=%s\n", opts.serverInfrastructureRef)
	fmt.Printf("TEST_PRIVATE_REGION_ID=%s\n", privateRegion)
	fmt.Printf("TEST_SECONDARY_ORG_ID=%s\n", secondaryOrgID)
	fmt.Printf("TEST_SECONDARY_AUTH_TOKEN=%s\n", secondaryToken)
	fmt.Printf("INTERNAL_API_CLIENT_CERT=%s\n", internalAPI.certPath)
	fmt.Printf("INTERNAL_API_CLIENT_KEY=%s\n", internalAPI.keyPath)
	fmt.Printf("INTERNAL_API_CN=%s\n", internalAPI.cn)
	fmt.Printf("INTERNAL_API_ACTOR=%s\n", primary.adminSAID)
}

func run(opts options) {
	opts = resolveCertPaths(opts)
	ctx := context.Background()
	k8s := newKubernetesClient()

	provider, testRegionID, existingRegion, err := resolveRegionFixture(ctx, k8s, opts.regionNamespace, opts.regionProvider, opts.testRegionID)
	if err != nil {
		fatalf("%v", err)
	}

	if existingRegion {
		logf("Using existing %s region fixture %s in namespace %s...", provider, testRegionID, opts.regionNamespace)
	}

	logf("Issuing mTLS client certificate for %s...", fixtureActor)
	certPEM, keyPEM := issueCert(ctx, k8s, opts.identityNamespace, fixtureActor, fixtureActor, opts.fixtureCertDuration)
	identityClient := newIdentityClient(opts.baseURL, opts.caCertPath, certPEM, keyPEM)

	logf("Creating primary identity fixtures...")

	primary := createPrimaryFixtures(ctx, identityClient, k8s, opts.identityNamespace)

	logf("Creating secondary identity fixtures...")

	secondaryOrgID, secondaryToken := createSecondaryFixtures(ctx, identityClient, k8s, opts.identityNamespace)

	logf("Issuing internal Region API client certificate for %s...", internalAPISystemAccountCN)
	internalCertPEM, internalKeyPEM := issueCert(ctx, k8s, opts.identityNamespace, internalAPICertificateName, internalAPISystemAccountCN, internalCertDuration)
	internalAPI := writeInternalAPICredentials(opts, internalCertPEM, internalKeyPEM)

	if provider == regionv1.ProviderSimulated && !existingRegion {
		logf("Creating simulated public region fixture in namespace %s...", opts.regionNamespace)
		upsertRegion(ctx, k8s, opts.regionNamespace, publicRegion, nil)
	}

	logf("Creating simulated private region fixture in namespace %s...", opts.regionNamespace)
	upsertRegion(ctx, k8s, opts.regionNamespace, privateRegion, []string{primary.orgID})

	emitEnv(opts, primary, secondaryOrgID, secondaryToken, testRegionID, internalAPI)
}
