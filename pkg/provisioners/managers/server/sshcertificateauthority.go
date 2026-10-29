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
	"context"
	"fmt"
	"path"
	"strings"

	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/providers/types"

	kerrors "k8s.io/apimachinery/pkg/api/errors"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	sshTrustedUserCAKeysPath   = "/etc/ssh/trusted-user-ca-keys.pub"
	sshTrustedUserCAConfigPath = "/etc/ssh/sshd_config.d/90-unikorn-trusted-user-ca.conf"
	// sshCertificateAuthorityPartName names our script in cloud-init's
	// scripts directory. Scripts run in name order and only once, so it
	// MUST sort before customer scripts, or one that reboots loses the CA
	// for good. See the README's "Managed cloud-init augmentation" section.
	sshCertificateAuthorityPartName = "00-unikorn-ssh-certificate-authority"
	sshReloadCommand                = "systemctl reload sshd || systemctl reload ssh || service ssh reload || service sshd reload || systemctl restart sshd || systemctl restart ssh || service ssh restart || service sshd restart"
)

func (p *Provisioner) getSSHCertificateAuthority(ctx context.Context, cli client.Client) (*unikornv1.SSHCertificateAuthority, error) {
	resource := &unikornv1.SSHCertificateAuthority{}

	if err := cli.Get(ctx, client.ObjectKey{Namespace: p.server.Namespace, Name: *p.server.Spec.SSHCertificateAuthorityID}, resource); err != nil {
		return nil, fmt.Errorf("%w: unable to lookup SSH certificate authority", err)
	}

	return resource, nil
}

// sshCertificateAuthorityPart is a shell script, not cloud-config: scripts
// are never merged with the customer's cloud-config, and cloud-init runs them
// once per instance. See the README's "Managed cloud-init augmentation" section.
func sshCertificateAuthorityPart(publicKey string) cloudInitPart {
	script := strings.Join([]string{
		"#!/bin/sh",
		"set -e",
		"umask 022",
		"mkdir -p " + path.Dir(sshTrustedUserCAConfigPath),
		"printf '%s\\n' " + shellQuote(publicKey) + " > " + sshTrustedUserCAKeysPath,
		"printf '%s\\n' " + shellQuote("TrustedUserCAKeys "+sshTrustedUserCAKeysPath) + " > " + sshTrustedUserCAConfigPath,
		"chown root:root " + sshTrustedUserCAKeysPath + " " + sshTrustedUserCAConfigPath,
		"chmod 0644 " + sshTrustedUserCAKeysPath + " " + sshTrustedUserCAConfigPath,
		sshReloadCommand,
		"",
	}, "\n")

	return cloudInitPart{
		ContentType: "text/x-shellscript",
		FileName:    sshCertificateAuthorityPartName,
		Content:     []byte(script),
	}
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func (p *Provisioner) serverCreateOptions(ctx context.Context, cli client.Client) (*types.ServerCreateOptions, error) {
	options := &types.ServerCreateOptions{
		UserData: p.server.Spec.UserData,
	}

	if p.server.Spec.SSHCertificateAuthorityID == nil {
		return options, nil
	}

	resource, err := p.getSSHCertificateAuthority(ctx, cli)
	if err != nil {
		// After boot nothing holds the CA, so the user may have deleted it; a
		// re-create then goes without it. Before boot the reference holds it.
		if p.server.Status.ProvisionedAt != nil && kerrors.IsNotFound(err) {
			return options, nil
		}

		return nil, err
	}

	userData, err := mergeCloudInitParts(p.server.Spec.UserData, sshCertificateAuthorityPart(resource.Spec.PublicKey))
	if err != nil {
		return nil, err
	}

	options.UserData = userData

	return options, nil
}
