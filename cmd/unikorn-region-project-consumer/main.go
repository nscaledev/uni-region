/*
Copyright 2025 the Unikorn Authors.

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

package main

import (
	"fmt"
	"os"

	"github.com/spf13/pflag"

	"github.com/unikorn-cloud/core/pkg/client"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/messaging/consumer"
	"github.com/unikorn-cloud/core/pkg/messaging/kubernetes"
	"github.com/unikorn-cloud/core/pkg/options"
	identityv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	regionv1 "github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/region/pkg/constants"

	cr "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

func main() {
	var options options.CoreOptions

	options.AddFlags(pflag.CommandLine)

	pflag.Parse()

	options.SetupLogging()

	logger := log.Log.WithName("init")
	logger.Info("service starting", "application", constants.Application, "version", constants.Version, "revision", constants.Revision)

	ctx := cr.SetupSignalHandler()

	// The consumer will listen for project deletion events and propagate them to
	// any root resources that have a corresponding project label.
	cli, err := client.New(ctx, regionv1.AddToScheme)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	consumer := consumer.NewCascadingDelete(cli, &regionv1.IdentityList{}, consumer.WithNamespace(options.Namespace), consumer.WithResourceLabel(coreconstants.ProjectLabel))

	scheme, err := client.NewScheme(identityv1.AddToScheme)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if err := kubernetes.New(cr.GetConfigOrDie(), scheme, &identityv1.Project{}, consumer).Run(ctx); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
