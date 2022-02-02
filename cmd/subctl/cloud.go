/*
SPDX-License-Identifier: Apache-2.0

Copyright Contributors to the Submariner project.

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

package subctl

import (
	"github.com/spf13/cobra"
	"github.com/submariner-io/cloud-prepare/pkg/api"
	"github.com/submariner-io/cloud-prepare/pkg/aws"
	"github.com/submariner-io/submariner-operator/internal/exit"
	"github.com/submariner-io/submariner-operator/pkg/cloud"
	"github.com/submariner-io/submariner-operator/pkg/cloud/prepare"
	"k8s.io/client-go/rest"
)

var (
	cloudCmd = &cobra.Command{
		Use:   "cloud",
		Short: "Cloud operations",
		Long:  `This command contains cloud operations related to Submariner installation.`,
	}
	port      cloud.Port
    instance  cloud.Instance
	cloudInfo cloud.Info
)

func init() {
	restConfigProducer.AddKubeContextFlag(cloudCmd)
	k8sConfig, err := restConfigProducer.ForCluster()
	exit.OnErrorWithMessage(err, "Failed to initialize a Kubernetes config")

	reporter := cloud.NewStatusReporter()

	cloudCmd.AddCommand(newPrepareCommand(k8sConfig, reporter))
	rootCmd.AddCommand(cloudCmd)
}

// addAWSFlags adds basic flags needed by AWS.
func addAWSFlags(command *cobra.Command) {
	command.Flags().StringVar(&cloudInfo.InfraID, cloud.InfraIDFlag, "", "AWS infra ID")
	command.Flags().StringVar(&cloudInfo.Region, cloud.RegionFlag, "", "AWS region")
	command.Flags().StringVar(&cloudInfo.OcpMetadataFile, "ocp-metadata", "",
		"OCP metadata.json file (or directory containing it) to read AWS infra ID and region from (Takes precedence over the flags)")
	command.Flags().StringVar(&cloudInfo.Profile, "profile", aws.DefaultProfile(), "AWS profile to use for credentials")
	command.Flags().StringVar(&cloudInfo.CredentialsFile, "credentials", aws.DefaultCredentialsFile(), "AWS credentials configuration file")
}

// newPrepareCommand returns a new cobra.Command used to prepare a cloud infrastructure.
func newPrepareCommand(config *rest.Config, reporter api.Reporter) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "prepare",
		Short: "Prepare the cloud",
		Long:  `This command prepares the cloud for Submariner installation.`,
	}

	cmd.PersistentFlags().Uint16Var(&port.Natt, "natt-port", 4500, "IPSec NAT traversal port")
	cmd.PersistentFlags().Uint16Var(&port.NatDiscovery, "nat-discovery-port", 4490, "NAT discovery port")
	cmd.PersistentFlags().Uint16Var(&port.VxLAN, "vxlan-port", 4800, "Internal VxLAN port")
	cmd.PersistentFlags().Uint16Var(&port.Metrics, "metrics-port", 8080, "Metrics port")

	cmd.AddCommand(newAWSPrepareCommand(config, reporter))

	return cmd
}

// NewCommand returns a new cobra.Command used to prepare a cloud infrastructure.
func newAWSPrepareCommand(config *rest.Config, reporter api.Reporter) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "aws",
		Short: "Prepare an OpenShift AWS cloud",
		Long:  "This command prepares an OpenShift installer-provisioned infrastructure (IPI) on AWS cloud for Submariner installation.",
		Run: func(cmd *cobra.Command, args []string) {
			err := prepare.Aws(port, instance, config, reporter)
			exit.OnErrorWithMessage(err, "Failed to prepare AWS cloud")
		},
	}

	addAWSFlags(cmd)
	cmd.Flags().StringVar(&instance.AWSGWType, "gateway-instance", "c5d.large", "Type of gateways instance machine")
	cmd.Flags().IntVar(&instance.Gateways, "gateways", cloud.DefaultNumGateways,
		"Number of dedicated gateways to deploy (Set to `0` when using --load-balancer mode)")

	return cmd
}