// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"fmt"
	"log/slog"
	"net"
	"slices"

	envoyAPI "github.com/cilium/proxy/go/cilium/api"
	cache_types "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	cache "github.com/envoyproxy/go-control-plane/pkg/cache/v3"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// nphdsCacheAdapter bridges the IPCache and the go-control-plane
// LinearCache used for NPHDS in the ADS implementation.
// It implements ipcache.IPIdentityMappingListener.
type nphdsCacheAdapter struct {
	logger *slog.Logger
	cache  *cache.LinearCache
}

var _ ipcache.IPIdentityMappingListener = (*nphdsCacheAdapter)(nil)

func newNPHDSCacheAdapter(logger *slog.Logger, cache *cache.LinearCache) *nphdsCacheAdapter {
	return &nphdsCacheAdapter{
		logger: logger,
		cache:  cache,
	}
}

// OnIPIdentityCacheChange pushes modifications to the IP<->Identity mapping
// into the NPHDS LinearCache, mirroring the old NPHDSCache behaviour.
func (a *nphdsCacheAdapter) OnIPIdentityCacheChange(modType ipcache.CacheModification, cidrCluster cmtypes.PrefixCluster,
	oldHostIP, newHostIP net.IP, oldID *ipcache.Identity, newID ipcache.Identity,
	encryptKey uint8, k8sMeta *ipcache.K8sMetadata, endpointFlags uint8,
) {
	cidr := cidrCluster.AsIPNet()
	cidrStr := cidr.String()
	resourceName := newID.ID.StringID()

	scopedLog := a.logger.With(
		logfields.IPAddr, cidrStr,
		logfields.Identity, resourceName,
		logfields.Modification, modType,
	)

	// Look up the current resource for this identity.
	var npHost *envoyAPI.NetworkPolicyHosts
	resources := a.cache.GetResources()
	if res, ok := resources[resourceName]; ok {
		npHost = res.(*envoyAPI.NetworkPolicyHosts)
	}

	switch modType {
	case ipcache.Upsert:
		// Delete the CIDR from the old identity first, if it changed.
		if oldID != nil && oldID.ID != newID.ID {
			a.OnIPIdentityCacheChange(ipcache.Delete, cidrCluster, nil, nil, nil, *oldID, encryptKey, k8sMeta, endpointFlags)
		}
		if err := a.handleIPUpsert(npHost, resourceName, cidrStr, newID.ID); err != nil {
			scopedLog.Warn("NPHDS upsert failed", logfields.Error, err)
		}
	case ipcache.Delete:
		if err := a.handleIPDelete(npHost, resourceName, cidrStr); err != nil {
			scopedLog.Warn("NPHDS delete failed", logfields.Error, err)
		}
	}
}

func (a *nphdsCacheAdapter) handleIPUpsert(npHost *envoyAPI.NetworkPolicyHosts, identityStr, cidrStr string, newID identity.NumericIdentity) error {
	var hostAddresses []string
	if npHost == nil {
		hostAddresses = []string{cidrStr}
	} else {
		if slices.Contains(npHost.HostAddresses, cidrStr) {
			return nil
		}
		hostAddresses = make([]string, 0, len(npHost.HostAddresses)+1)
		hostAddresses = append(hostAddresses, npHost.HostAddresses...)
		hostAddresses = append(hostAddresses, cidrStr)
		slices.Sort(hostAddresses)
	}

	newNpHost := &envoyAPI.NetworkPolicyHosts{
		Policy:        uint64(newID),
		HostAddresses: hostAddresses,
	}
	if err := newNpHost.Validate(); err != nil {
		return fmt.Errorf("could not validate NPHDS resource update on upsert: %s (%w)", newNpHost.String(), err)
	}
	return a.cache.UpdateResources(map[string]cache_types.Resource{identityStr: newNpHost}, nil)
}

func (a *nphdsCacheAdapter) handleIPDelete(npHost *envoyAPI.NetworkPolicyHosts, identityStr, cidrStr string) error {
	if npHost == nil {
		return nil
	}

	targetIndex := slices.Index(npHost.HostAddresses, cidrStr)
	if targetIndex < 0 {
		return fmt.Errorf("can't find IP %s in NPHDS cache for identity %s", cidrStr, identityStr)
	}

	if len(npHost.HostAddresses) <= 1 {
		return a.cache.UpdateResources(nil, []string{identityStr})
	}

	hostAddresses := make([]string, 0, len(npHost.HostAddresses)-1)
	hostAddresses = append(hostAddresses, npHost.HostAddresses[:targetIndex]...)
	hostAddresses = append(hostAddresses, npHost.HostAddresses[targetIndex+1:]...)

	newNpHost := &envoyAPI.NetworkPolicyHosts{
		Policy:        npHost.Policy,
		HostAddresses: hostAddresses,
	}
	if err := newNpHost.Validate(); err != nil {
		return fmt.Errorf("could not validate NPHDS resource update on delete: %s (%w)", newNpHost.String(), err)
	}
	return a.cache.UpdateResources(map[string]cache_types.Resource{identityStr: newNpHost}, nil)
}

// startNPHDSIPCacheListener starts listening to IPCache events and populating
// the NPHDS LinearCache.
func startNPHDSIPCacheListener(logger *slog.Logger, ipCache IPCacheEventSource, nphdsCache *cache.LinearCache) {
	if ipCache == nil {
		return
	}
	adapter := newNPHDSCacheAdapter(logger, nphdsCache)
	ipCache.AddListener(adapter)
}
