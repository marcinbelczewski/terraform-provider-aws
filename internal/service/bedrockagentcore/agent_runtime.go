// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package bedrockagentcore

import (
	"context"
	"errors"
	"time"

	"github.com/YakDriver/smarterr"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol"
	awstypes "github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol/types"
	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	sdkretry "github.com/hashicorp/terraform-plugin-sdk/v2/helper/retry"
	"github.com/hashicorp/terraform-provider-aws/internal/enum"
	"github.com/hashicorp/terraform-provider-aws/internal/errs"
	"github.com/hashicorp/terraform-provider-aws/internal/errs/fwdiag"
	"github.com/hashicorp/terraform-provider-aws/internal/framework"
	"github.com/hashicorp/terraform-provider-aws/internal/framework/flex"
	fwtypes "github.com/hashicorp/terraform-provider-aws/internal/framework/types"
	"github.com/hashicorp/terraform-provider-aws/internal/retry"
	"github.com/hashicorp/terraform-provider-aws/internal/smerr"
	"github.com/hashicorp/terraform-provider-aws/internal/tfresource"
	"github.com/hashicorp/terraform-provider-aws/names"
)

// Function annotations are used for resource registration to the Provider. DO NOT EDIT.
// @FrameworkResource("aws_bedrockagentcore_agent_runtime", name="Agent Runtime")
func newResourceAgentRuntime(_ context.Context) (resource.ResourceWithConfigure, error) {
	r := &resourceAgentRuntime{}

	r.SetDefaultCreateTimeout(30 * time.Minute)
	r.SetDefaultUpdateTimeout(30 * time.Minute)
	r.SetDefaultDeleteTimeout(30 * time.Minute)

	return r, nil
}

const (
	ResNameAgentRuntime = "Agent Runtime"
)

type resourceAgentRuntime struct {
	framework.ResourceWithModel[ResourceAgentRuntimeModel]
	framework.WithTimeouts
	framework.WithImportByID
}

func (r *resourceAgentRuntime) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			names.AttrARN: framework.ARNAttributeComputedOnly(),

			names.AttrID: framework.IDAttribute(),

			names.AttrName: schema.StringAttribute{
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},

			names.AttrDescription: schema.StringAttribute{
				Optional: true,
			},

			names.AttrRoleARN: schema.StringAttribute{
				Required: true,
			},

			"environment_variables": schema.MapAttribute{
				CustomType: fwtypes.MapOfStringType,
				Optional:   true,
			},
			"client_token": schema.StringAttribute{
				Optional: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			names.AttrVersion: schema.StringAttribute{
				Computed: true,
			},
			// TODO(v6): Replace `schema.ObjectAttribute` with `schema.SingleNestedAttribute` once
			// provider‑protocol v6 is available. At that point we can expose the inner
			// `artifact.container_configuration` fields directly in the schema so each
			// can carry its own Optional/Computed/Validator rules.
			"artifact": schema.ObjectAttribute{
				CustomType: fwtypes.NewObjectTypeOf[ArtifactModel](ctx),
				Required:   true,
			},
			// TODO(v6): Switch this to `schema.SingleNestedAttribute` so the nested fields
			// (`discovery_url`, `allowed_audience`, `allowed_clients`) become first‑class
			// attributes.
			//
			// * **Protocol‑v5 trade‑off** – Terraform Core demands that every key of an
			//   `schema.ObjectAttribute` be present, so practitioners must supply *both*
			//   set attributes and set the unused one to `null`.  Passing an explicit
			//   `null` is something we usually avoid because it clutters configuration,
			//   but here it is the only pragmatic way to satisfy all of:
			//
			//       1. Prefer nested attributes over blocks *and*
			//       2. Core’s “all keys required” rule, *and*
			//       3. The Bedrock API rule that *at least one* of the sets contains a
			//          value.
			//
			//   There is therefore never a situation where *both* sets are `null`; at
			//   most one of them is so it seems an acceptable trade off.
			//
			// * **Protocol‑v6 solution** – Nested attributes let each set be truly
			//   `Optional`.  Users will then omit the unused set entirely—no more
			//   explicit `null`.  Older configs that still send `null` will remain
			//   accepted, so the upgrade is non‑breaking.
			"authorizer_configuration": schema.ObjectAttribute{
				CustomType: fwtypes.NewObjectTypeOf[AuthorizerConfigurationModel](ctx),
				Optional:   true,
			},
			// TODO(v6): Convert to `schema.SingleNestedAttribute` and move the `"PUBLIC"`
			// default onto the `network_mode` attribute itself.
			//
			// The AWS API today supports **only one** networking mode (`"PUBLIC"`), while
			// treating the overall `network_configuration` object as required.  Making
			// the block `Optional + Computed` and injecting an object‑level default frees
			// users from writing the same boiler‑plate every time:
			//
			//     network_configuration {
			//       network_mode = "PUBLIC"
			//     }
			//
			// Once new modes appear, we will expose `network_mode` as its own nested
			// attribute with an attribute‑level default.  Configurations that currently
			// omit the block will continue to work unchanged.
			names.AttrNetworkConfiguration: schema.ObjectAttribute{
				CustomType: fwtypes.NewObjectTypeOf[NetworkConfigurationModel](ctx),
				Optional:   true,
				Computed:   true,
				Default: objectdefault.StaticValue(
					types.ObjectValueMust(
						map[string]attr.Type{
							"network_mode": types.StringType,
						},
						map[string]attr.Value{
							"network_mode": types.StringValue("PUBLIC"),
						},
					),
				),
				PlanModifiers: []planmodifier.Object{
					objectplanmodifier.UseStateForUnknown(),
				},
			},
			// TODO(v6): Convert to `schema.SingleNestedAttribute` and surface the nested
			// attributes (`server_protocol`, etc.) with proper enums/validators.
			"protocol_configuration": schema.ObjectAttribute{
				CustomType: fwtypes.NewObjectTypeOf[ProtocolConfigurationModel](ctx),
				Optional:   true,
			},
			// TODO(v6): Convert to `schema.SingleNestedAttribute`. Attribute remains
			// Computed‑only; switching syntax removes opaque object types from state.
			"workload_identity_details": schema.ObjectAttribute{
				CustomType: fwtypes.NewObjectTypeOf[WorkloadIdentityDetailsModel](ctx),
				Computed:   true,
			},
		},

		Blocks: map[string]schema.Block{
			names.AttrTimeouts: timeouts.Block(ctx, timeouts.Opts{
				Create: true,
				Update: true,
				Delete: true,
			}),
		},
	}
}

func (r *resourceAgentRuntime) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	conn := r.Meta().BedrockAgentCoreClient(ctx)

	var plan ResourceAgentRuntimeModel
	smerr.EnrichAppend(ctx, &resp.Diagnostics, req.Plan.Get(ctx, &plan))
	if resp.Diagnostics.HasError() {
		return
	}

	var input bedrockagentcorecontrol.CreateAgentRuntimeInput
	smerr.EnrichAppend(ctx, &resp.Diagnostics, flex.Expand(ctx, plan, &input, flex.WithFieldNamePrefix("AgentRuntime")))
	if resp.Diagnostics.HasError() {
		return
	}

	out, err := conn.CreateAgentRuntime(ctx, &input)
	if err != nil {
		smerr.AddError(ctx, &resp.Diagnostics, err, smerr.ID, plan.Name.String())
		return
	}
	if out == nil {
		smerr.AddError(ctx, &resp.Diagnostics, errors.New("empty output"), smerr.ID, plan.Name.String())
		return
	}

	smerr.EnrichAppend(ctx, &resp.Diagnostics, flex.Flatten(ctx, out, &plan, flex.WithFieldNamePrefix("AgentRuntime")))
	if resp.Diagnostics.HasError() {
		return
	}

	createTimeout := r.CreateTimeout(ctx, plan.Timeouts)
	_, err = waitAgentRuntimeCreated(ctx, conn, plan.ID.ValueString(), createTimeout)
	if err != nil {
		smerr.AddError(ctx, &resp.Diagnostics, err, smerr.ID, plan.Name.String())
		return
	}

	smerr.EnrichAppend(ctx, &resp.Diagnostics, resp.State.Set(ctx, plan))
}

func (r *resourceAgentRuntime) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	conn := r.Meta().BedrockAgentCoreClient(ctx)

	var state ResourceAgentRuntimeModel
	smerr.EnrichAppend(ctx, &resp.Diagnostics, req.State.Get(ctx, &state))
	if resp.Diagnostics.HasError() {
		return
	}

	out, err := findAgentRuntimeByID(ctx, conn, state.ID.ValueString())
	if tfresource.NotFound(err) {
		resp.Diagnostics.Append(fwdiag.NewResourceNotFoundWarningDiagnostic(err))
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		smerr.AddError(ctx, &resp.Diagnostics, err, smerr.ID, state.ID.String())
		return
	}

	smerr.EnrichAppend(ctx, &resp.Diagnostics, flex.Flatten(ctx, out, &state, flex.WithFieldNamePrefix("AgentRuntime")))
	if resp.Diagnostics.HasError() {
		return
	}

	smerr.EnrichAppend(ctx, &resp.Diagnostics, resp.State.Set(ctx, &state))
}

func (r *resourceAgentRuntime) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	conn := r.Meta().BedrockAgentCoreClient(ctx)

	var plan, state ResourceAgentRuntimeModel
	smerr.EnrichAppend(ctx, &resp.Diagnostics, req.Plan.Get(ctx, &plan))
	smerr.EnrichAppend(ctx, &resp.Diagnostics, req.State.Get(ctx, &state))
	if resp.Diagnostics.HasError() {
		return
	}

	diff, d := flex.Diff(ctx, plan, state)
	smerr.EnrichAppend(ctx, &resp.Diagnostics, d)
	if resp.Diagnostics.HasError() {
		return
	}

	if diff.HasChanges() {
		var input bedrockagentcorecontrol.UpdateAgentRuntimeInput
		smerr.EnrichAppend(ctx, &resp.Diagnostics, flex.Expand(ctx, plan, &input, flex.WithFieldNamePrefix("AgentRuntime")))
		if resp.Diagnostics.HasError() {
			return
		}

		out, err := conn.UpdateAgentRuntime(ctx, &input)
		if err != nil {
			smerr.AddError(ctx, &resp.Diagnostics, err, smerr.ID, plan.ID.String())
			return
		}
		if out == nil {
			smerr.AddError(ctx, &resp.Diagnostics, errors.New("empty output"), smerr.ID, plan.ID.String())
			return
		}

		smerr.EnrichAppend(ctx, &resp.Diagnostics, flex.Flatten(ctx, out, &plan, flex.WithFieldNamePrefix("AgentRuntime")))
		if resp.Diagnostics.HasError() {
			return
		}
	}

	updateTimeout := r.UpdateTimeout(ctx, plan.Timeouts)
	_, err := waitAgentRuntimeUpdated(ctx, conn, plan.ID.ValueString(), updateTimeout)
	if err != nil {
		smerr.AddError(ctx, &resp.Diagnostics, err, smerr.ID, plan.ID.String())
		return
	}

	smerr.EnrichAppend(ctx, &resp.Diagnostics, resp.State.Set(ctx, &plan))
}

func (r *resourceAgentRuntime) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	conn := r.Meta().BedrockAgentCoreClient(ctx)

	var state ResourceAgentRuntimeModel
	smerr.EnrichAppend(ctx, &resp.Diagnostics, req.State.Get(ctx, &state))
	if resp.Diagnostics.HasError() {
		return
	}

	input := bedrockagentcorecontrol.DeleteAgentRuntimeInput{
		AgentRuntimeId: state.ID.ValueStringPointer(),
	}

	_, err := conn.DeleteAgentRuntime(ctx, &input)
	if err != nil {
		if errs.IsA[*awstypes.ResourceNotFoundException](err) {
			return
		}

		smerr.AddError(ctx, &resp.Diagnostics, err, smerr.ID, state.ID.String())
		return
	}

	deleteTimeout := r.DeleteTimeout(ctx, state.Timeouts)
	_, err = waitAgentRuntimeDeleted(ctx, conn, state.ID.ValueString(), deleteTimeout)
	if err != nil {
		smerr.AddError(ctx, &resp.Diagnostics, err, smerr.ID, state.ID.String())
		return
	}
}

func waitAgentRuntimeCreated(ctx context.Context, conn *bedrockagentcorecontrol.Client, id string, timeout time.Duration) (*bedrockagentcorecontrol.GetAgentRuntimeOutput, error) {
	stateConf := &sdkretry.StateChangeConf{
		Pending:                   enum.Slice(awstypes.AgentStatusCreating),
		Target:                    enum.Slice(awstypes.AgentStatusReady),
		Refresh:                   statusAgentRuntime(ctx, conn, id),
		Timeout:                   timeout,
		NotFoundChecks:            20,
		ContinuousTargetOccurence: 2,
	}

	outputRaw, err := stateConf.WaitForStateContext(ctx)
	if out, ok := outputRaw.(*bedrockagentcorecontrol.GetAgentRuntimeOutput); ok {
		return out, smarterr.NewError(err)
	}

	return nil, smarterr.NewError(err)
}

func waitAgentRuntimeUpdated(ctx context.Context, conn *bedrockagentcorecontrol.Client, id string, timeout time.Duration) (*bedrockagentcorecontrol.GetAgentRuntimeOutput, error) {
	stateConf := &sdkretry.StateChangeConf{
		Pending:                   enum.Slice(awstypes.AgentStatusUpdating),
		Target:                    enum.Slice(awstypes.AgentStatusReady),
		Refresh:                   statusAgentRuntime(ctx, conn, id),
		Timeout:                   timeout,
		NotFoundChecks:            20,
		ContinuousTargetOccurence: 2,
	}

	outputRaw, err := stateConf.WaitForStateContext(ctx)
	if out, ok := outputRaw.(*bedrockagentcorecontrol.GetAgentRuntimeOutput); ok {
		return out, smarterr.NewError(err)
	}

	return nil, smarterr.NewError(err)
}

func waitAgentRuntimeDeleted(ctx context.Context, conn *bedrockagentcorecontrol.Client, id string, timeout time.Duration) (*bedrockagentcorecontrol.GetAgentRuntimeOutput, error) {
	stateConf := &sdkretry.StateChangeConf{
		Pending: enum.Slice(awstypes.AgentStatusDeleting, awstypes.AgentStatusReady),
		Target:  []string{},
		Refresh: statusAgentRuntime(ctx, conn, id),
		Timeout: timeout,
	}

	outputRaw, err := stateConf.WaitForStateContext(ctx)
	if out, ok := outputRaw.(*bedrockagentcorecontrol.GetAgentRuntimeOutput); ok {
		return out, smarterr.NewError(err)
	}

	return nil, smarterr.NewError(err)
}

func statusAgentRuntime(ctx context.Context, conn *bedrockagentcorecontrol.Client, id string) sdkretry.StateRefreshFunc {
	return func() (any, string, error) {
		out, err := findAgentRuntimeByID(ctx, conn, id)
		if retry.NotFound(err) {
			return nil, "", nil
		}

		if err != nil {
			return nil, "", smarterr.NewError(err)
		}

		return out, string(out.Status), nil
	}
}

func findAgentRuntimeByID(ctx context.Context, conn *bedrockagentcorecontrol.Client, id string) (*bedrockagentcorecontrol.GetAgentRuntimeOutput, error) {
	input := bedrockagentcorecontrol.GetAgentRuntimeInput{
		AgentRuntimeId: aws.String(id),
	}

	out, err := conn.GetAgentRuntime(ctx, &input)
	if err != nil {
		if errs.IsA[*awstypes.ResourceNotFoundException](err) {
			return nil, smarterr.NewError(&sdkretry.NotFoundError{
				LastError:   err,
				LastRequest: &input,
			})
		}

		return nil, smarterr.NewError(err)
	}

	if out == nil {
		return nil, smarterr.NewError(tfresource.NewEmptyResultError(&input))
	}

	return out, nil
}

type ResourceAgentRuntimeModel struct {
	framework.WithRegionModel

	ARN         types.String `tfsdk:"arn"`
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	RoleArn     types.String `tfsdk:"role_arn"`
	ClientToken types.String `tfsdk:"client_token"`
	Version     types.String `tfsdk:"version"`

	EnvironmentVariables    fwtypes.MapOfString                                 `tfsdk:"environment_variables"`
	Artifact                fwtypes.ObjectValueOf[ArtifactModel]                `tfsdk:"artifact"`
	AuthorizerConfiguration fwtypes.ObjectValueOf[AuthorizerConfigurationModel] `tfsdk:"authorizer_configuration"`
	NetworkConfiguration    fwtypes.ObjectValueOf[NetworkConfigurationModel]    `tfsdk:"network_configuration"`
	ProtocolConfiguration   fwtypes.ObjectValueOf[ProtocolConfigurationModel]   `tfsdk:"protocol_configuration"`
	WorkloadIdentityDetails fwtypes.ObjectValueOf[WorkloadIdentityDetailsModel] `tfsdk:"workload_identity_details"`

	Timeouts timeouts.Value `tfsdk:"timeouts"`
}

type ArtifactModel struct {
	ContainerConfiguration fwtypes.ObjectValueOf[ContainerConfigurationModel] `tfsdk:"container_configuration"`
}

func (m *ArtifactModel) Flatten(ctx context.Context, v any) (diags diag.Diagnostics) {
	switch t := v.(type) {
	case awstypes.AgentArtifactMemberContainerConfiguration:
		var model ContainerConfigurationModel
		d := flex.Flatten(ctx, t.Value, &model)
		diags.Append(d...)
		if diags.HasError() {
			return diags
		}
		m.ContainerConfiguration = fwtypes.NewObjectValueOfMust(ctx, &model)
		return diags

	default:
		return diags
	}
}

func (m ArtifactModel) Expand(ctx context.Context) (result any, diags diag.Diagnostics) {
	switch {
	case !m.ContainerConfiguration.IsNull():
		model, d := m.ContainerConfiguration.ToPtr(ctx)
		diags.Append(d...)
		if diags.HasError() {
			return nil, diags
		}
		var r awstypes.AgentArtifactMemberContainerConfiguration
		diags.Append(flex.Expand(ctx, model, &r.Value)...)
		if diags.HasError() {
			return nil, diags
		}
		return &r, diags
	}
	return nil, diags
}

type ContainerConfigurationModel struct {
	ContainerUri types.String `tfsdk:"container_uri"`
}

type AuthorizerConfigurationModel struct {
	CustomJWTAuthorizer fwtypes.ObjectValueOf[CustomJWTAuthorizerConfigurationModel] `tfsdk:"custom_jwt_authorizer"`
}

func (m *AuthorizerConfigurationModel) Flatten(ctx context.Context, v any) (diags diag.Diagnostics) {
	switch t := v.(type) {
	case awstypes.AuthorizerConfigurationMemberCustomJWTAuthorizer:
		var model CustomJWTAuthorizerConfigurationModel
		d := flex.Flatten(ctx, t.Value, &model)
		diags.Append(d...)
		if diags.HasError() {
			return diags
		}
		m.CustomJWTAuthorizer = fwtypes.NewObjectValueOfMust(ctx, &model)
		return diags

	default:
		return diags
	}
}

func (m AuthorizerConfigurationModel) Expand(ctx context.Context) (result any, diags diag.Diagnostics) {
	switch {
	case !m.CustomJWTAuthorizer.IsNull():
		model, d := m.CustomJWTAuthorizer.ToPtr(ctx)
		diags.Append(d...)
		if diags.HasError() {
			return nil, diags
		}
		var r awstypes.AuthorizerConfigurationMemberCustomJWTAuthorizer
		diags.Append(flex.Expand(ctx, model, &r.Value)...)
		if diags.HasError() {
			return nil, diags
		}
		return &r, diags
	}
	return nil, diags
}

type CustomJWTAuthorizerConfigurationModel struct {
	DiscoveryUrl    types.String        `tfsdk:"discovery_url"`
	AllowedAudience fwtypes.SetOfString `tfsdk:"allowed_audience"`
	AllowedClients  fwtypes.SetOfString `tfsdk:"allowed_clients"`
}

type NetworkConfigurationModel struct {
	NetworkMode types.String `tfsdk:"network_mode"` // Enum: "PUBLIC"
}

type ProtocolConfigurationModel struct {
	ServerProtocol types.String `tfsdk:"server_protocol"` // Enum: "MCP", "HTTP"
}

type WorkloadIdentityDetailsModel struct {
	WorkloadIdentityArn types.String `tfsdk:"workload_identity_arn"`
}
