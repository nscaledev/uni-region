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

	unikornv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/providers/types"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	sshTrustedUserCAKeysPath        = "/etc/ssh/trusted-user-ca-keys.pub"
	sshTrustedUserCAConfigPath      = "/etc/ssh/sshd_config.d/90-unikorn-trusted-user-ca.conf"
	sshCertificateAuthorityPartName = "unikorn-ssh-certificate-authority"
	sshReloadCommand                = "systemctl reload sshd || systemctl reload ssh || service ssh reload || service sshd reload || systemctl restart sshd || systemctl restart ssh || service ssh restart || service sshd restart"
)

func (p *Provisioner) getSSHCertificateAuthority(ctx context.Context, cli client.Client) (*unikornv1.SSHCertificateAuthority, error) {
	resource := &unikornv1.SSHCertificateAuthority{}

	if err := cli.Get(ctx, client.ObjectKey{Namespace: p.server.Namespace, Name: *p.server.Spec.SSHCertificateAuthorityID}, resource); err != nil {
		return nil, fmt.Errorf("%w: unable to lookup SSH certificate authority", err)
	}

	return resource, nil
}

func sshCertificateAuthorityCloudConfigPart(publicKey string) (*cloudInitPart, error) {
	return cloudConfigPart(&cloudConfig{
		WriteFiles: []cloudConfigWriteFile{
			{
				Path:        sshTrustedUserCAKeysPath,
				Owner:       "root:root",
				Permissions: "0644",
				Content:     publicKey,
			},
			{
				Path:        sshTrustedUserCAConfigPath,
				Owner:       "root:root",
				Permissions: "0644",
				Content:     "TrustedUserCAKeys " + sshTrustedUserCAKeysPath,
			},
		},
		RunCmd: [][]string{
			{"sh", "-c", sshReloadCommand},
		},
	}, sshCertificateAuthorityPartName)
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
		return nil, err
	}

	part, err := sshCertificateAuthorityCloudConfigPart(resource.Spec.PublicKey)
	if err != nil {
		return nil, err
	}

	userData, err := mergeCloudInitParts(p.server.Spec.UserData, *part)
	if err != nil {
		return nil, err
	}

	options.UserData = userData

	return options, nil
}
