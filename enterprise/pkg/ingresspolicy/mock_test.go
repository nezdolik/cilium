//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package ingresspolicy

import (
	"context"

	cilium "github.com/cilium/proxy/go/cilium/api"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy/endpoint"
)

var _ xds.XDSServer = &mockXDSServer{}

type mockXDSServer struct {
	nrOfDeletions int
	nrOfUpdates   int
	nrOfUpserts   int

	policies map[string]*policy.L4Policy
}

func newMockXdsServer() *mockXDSServer {
	return &mockXDSServer{
		policies: map[string]*policy.L4Policy{},
	}
}

func (r *mockXDSServer) Reset() {
	r.nrOfUpdates = 0
	r.nrOfUpserts = 0
	r.nrOfDeletions = 0
}

func (r *mockXDSServer) UpdateEnvoyResources(ctx context.Context, old xds.Resources, new xds.Resources) error {
	r.nrOfUpdates++
	return nil
}

func (r *mockXDSServer) DeleteEnvoyResources(ctx context.Context, resources xds.Resources) error {
	r.nrOfDeletions++
	return nil
}

func (r *mockXDSServer) UpsertEnvoyResources(ctx context.Context, resources xds.Resources) error {
	r.nrOfUpserts++
	return nil
}

func (*mockXDSServer) AddListener(name string, kind policy.L7ParserType, port uint16, isIngress bool, mayUseOriginalSourceAddr bool, wg *completion.WaitGroup, cb func(err error)) error {
	panic("unimplemented")
}

func (*mockXDSServer) AddAdminListener(port uint16, wg *completion.WaitGroup) {
	panic("unimplemented")
}

func (*mockXDSServer) AddMetricsListener(port uint16, wg *completion.WaitGroup) {
	panic("unimplemented")
}

func (*mockXDSServer) GetNetworkPolicies(resourceNames []string) (map[string]*cilium.NetworkPolicy, error) {
	panic("unimplemented")
}

func (s *mockXDSServer) RemoveAllNetworkPolicies() {
	panic("unimplemented")
}

func (s *mockXDSServer) RemoveListener(name string, wg *completion.WaitGroup) xds.AckingResourceMutatorRevertFunc {
	panic("unimplemented")
}

func (s *mockXDSServer) RemoveNetworkPolicy(ep endpoint.EndpointInfoSource) {
	s.nrOfDeletions++
	delete(s.policies, ep.GetPolicyNames()[0])
}

func (s *mockXDSServer) UpdateNetworkPolicy(ep endpoint.EndpointUpdater, policy *policy.L4Policy, ingressPolicyEnforced bool, egressPolicyEnforced bool, wg *completion.WaitGroup) (error, func() error) {
	if !ep.GetPolicyVersionHandle().IsValid() {
		panic("UpdateNetworkPolicy called with invalid version")
	}
	s.nrOfUpdates++
	s.policies[ep.GetPolicyNames()[0]] = policy
	return nil, func() error { return nil }
}

func (*mockXDSServer) UseCurrentNetworkPolicy(ep endpoint.EndpointUpdater, policy *policy.L4Policy, wg *completion.WaitGroup) {
	panic("unimplemented")
}

func (*mockXDSServer) GetPolicySecretSyncNamespace() string {
	panic("unimplemented")
}

func (*mockXDSServer) SetPolicySecretSyncNamespace(string) {
	panic("unimplemented")
}
