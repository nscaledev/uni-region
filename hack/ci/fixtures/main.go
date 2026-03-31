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
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	coreopenapi "github.com/unikorn-cloud/core/pkg/openapi"
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
	fixtureActor  = "ci-fixtures"
	publicRegion  = "sim-public"
	privateRegion = "sim-private"
)

func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "ERROR: "+format+"\n", args...)
	os.Exit(1)
}

func logf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "==> "+format+"\n", args...)
}

func issueCert(ctx context.Context, k8s client.Client, namespace, name, cn string) ([]byte, []byte) {
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
		"duration":   "1h",
		"issuerRef": map[string]interface{}{
			"name":  "unikorn-client-issuer",
			"kind":  "ClusterIssuer",
			"group": "cert-manager.io",
		},
	}

	if err := k8s.Create(ctx, cert); client.IgnoreAlreadyExists(err) != nil {
		fatalf("failed to create Certificate %s: %v", name, err)
	}

	if err := wait.PollUntilContextTimeout(ctx, 2*time.Second, 60*time.Second, true, func(ctx context.Context) (bool, error) {
		current := &unstructured.Unstructured{}
		current.SetGroupVersionKind(cert.GroupVersionKind())

		if err := k8s.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, current); err != nil {
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
		fatalf("Certificate %s/%s not ready: %v", namespace, name, err)
	}

	secret := &corev1.Secret{}
	if err := k8s.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name + "-tls"}, secret); err != nil {
		fatalf("failed to read Secret %s-tls: %v", name, err)
	}

	return secret.Data["tls.crt"], secret.Data["tls.key"]
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
	rolesResp, err := ac.GetApiV1OrganizationsOrganizationIDRolesWithResponse(ctx, orgID)
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
	resp, err := ac.PostApiV1OrganizationsOrganizationIDGroupsWithResponse(ctx, orgID, identityopenapi.GroupWrite{
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
	resp, err := ac.PostApiV1OrganizationsOrganizationIDProjectsWithResponse(ctx, orgID, identityopenapi.ProjectWrite{
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
	resp, err := ac.PostApiV1OrganizationsOrganizationIDServiceaccountsWithResponse(ctx, orgID, identityopenapi.ServiceAccountWrite{
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

func main() {
	opts := parseOptions()
	run(opts)
}

type options struct {
	baseURL           string
	identityNamespace string
	regionNamespace   string
	regionBaseURL     string
	caCertPath        string
	regionCACertPath  string
}

func parseOptions() options {
	baseURL := flag.String("base-url", os.Getenv("IDENTITY_BASE_URL"), "Identity service base URL")
	identityNamespace := flag.String("identity-namespace", os.Getenv("IDENTITY_NAMESPACE"), "Identity Kubernetes namespace")
	regionNamespace := flag.String("region-namespace", os.Getenv("REGION_NAMESPACE"), "Region Kubernetes namespace")
	regionBaseURL := flag.String("region-base-url", os.Getenv("REGION_BASE_URL"), "Region service base URL")
	caCertPath := flag.String("ca-cert", os.Getenv("IDENTITY_CA_CERT"), "Path to CA certificate bundle")
	regionCACertPath := flag.String("region-ca-cert", os.Getenv("REGION_CA_CERT"), "Path to region CA certificate bundle")
	flag.Parse()

	if *baseURL == "" || *identityNamespace == "" || *regionNamespace == "" || *regionBaseURL == "" || *caCertPath == "" {
		fmt.Fprintln(os.Stderr, "Usage: fixtures --base-url URL --identity-namespace NS --region-namespace NS --region-base-url URL --ca-cert PATH [--region-ca-cert PATH]")
		os.Exit(1)
	}

	return options{
		baseURL:           *baseURL,
		identityNamespace: *identityNamespace,
		regionNamespace:   *regionNamespace,
		regionBaseURL:     *regionBaseURL,
		caCertPath:        *caCertPath,
		regionCACertPath:  *regionCACertPath,
	}
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

func emitEnv(opts options, primary primaryFixture, secondaryOrgID, secondaryToken string) {
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
	fmt.Printf("TEST_REGION_ID=%s\n", publicRegion)
	fmt.Printf("TEST_PRIVATE_REGION_ID=%s\n", privateRegion)
	fmt.Printf("TEST_SECONDARY_ORG_ID=%s\n", secondaryOrgID)
	fmt.Printf("TEST_SECONDARY_AUTH_TOKEN=%s\n", secondaryToken)
}

func run(opts options) {
	opts = resolveCertPaths(opts)
	ctx := context.Background()
	k8s := newKubernetesClient()

	logf("Issuing mTLS client certificate for %s...", fixtureActor)
	certPEM, keyPEM := issueCert(ctx, k8s, opts.identityNamespace, fixtureActor, fixtureActor)
	identityClient := newIdentityClient(opts.baseURL, opts.caCertPath, certPEM, keyPEM)

	logf("Creating primary identity fixtures...")

	primary := createPrimaryFixtures(ctx, identityClient, k8s, opts.identityNamespace)

	logf("Creating secondary identity fixtures...")

	secondaryOrgID, secondaryToken := createSecondaryFixtures(ctx, identityClient, k8s, opts.identityNamespace)

	logf("Creating simulated region fixtures in namespace %s...", opts.regionNamespace)
	upsertRegion(ctx, k8s, opts.regionNamespace, publicRegion, nil)
	upsertRegion(ctx, k8s, opts.regionNamespace, privateRegion, []string{primary.orgID})
	emitEnv(opts, primary, secondaryOrgID, secondaryToken)
}
