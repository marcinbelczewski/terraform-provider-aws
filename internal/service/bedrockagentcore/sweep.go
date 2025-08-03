// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package bedrockagentcore

import (
	"context"

	"github.com/YakDriver/smarterr"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
	"github.com/hashicorp/terraform-provider-aws/internal/sweep"
	"github.com/hashicorp/terraform-provider-aws/internal/sweep/awsv2"
	"github.com/hashicorp/terraform-provider-aws/internal/sweep/framework"
	"github.com/hashicorp/terraform-provider-aws/names"
)

func RegisterSweepers() {
	awsv2.Register("aws_bedrockagentcore_agent_runtime", sweepAgentRuntimes)
}

func sweepAgentRuntimes(ctx context.Context, client *conns.AWSClient) ([]sweep.Sweepable, error) {
	input := bedrockagentcorecontrol.ListAgentRuntimesInput{}
	conn := client.BedrockAgentCoreClient(ctx)
	var sweepResources []sweep.Sweepable

	pages := bedrockagentcorecontrol.NewListAgentRuntimesPaginator(conn, &input)
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return nil, smarterr.NewError(err)
		}

		for _, v := range page.AgentRuntimes {
			sweepResources = append(sweepResources, framework.NewSweepResource(newResourceAgentRuntime, client,
				framework.NewAttribute(names.AttrID, aws.ToString(v.AgentRuntimeId))),
			)
		}
	}

	return sweepResources, nil
}
