/*
Copyright 2022-2024 EscherCloud.
Copyright 2024-2025 the Unikorn Authors.
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

package handler

import (
	"github.com/unikorn-cloud/region/pkg/handler/common"
)

type Handler struct {
	// There are embedded so they can be their own structs
	*IdentityHandler
	*ImageHandler
	*ImageV2Handler
	*NetworkHandler
	*RegionHandler
	*SecurityGroupHandler
	*ServerHandler

	// ClientArgs has the values needed to create the various handler clients.
	common.ClientArgs

	// options allows behaviour to be defined on the CLI.
	options *Options
}

func New(clientArgs common.ClientArgs, options *Options) (*Handler, error) {
	h := &Handler{
		ClientArgs:           clientArgs,
		options:              options,
		IdentityHandler:      NewIdentityHandler(clientArgs),
		ImageHandler:         NewImageHandler(clientArgs, options),
		ImageV2Handler:       NewImageV2Handler(clientArgs, options),
		NetworkHandler:       NewNetworkHandler(clientArgs),
		RegionHandler:        NewRegionHandler(clientArgs, options),
		SecurityGroupHandler: NewSecurityGroupHandler(clientArgs),
		ServerHandler:        NewServerHandler(clientArgs),
	}

	return h, nil
}
