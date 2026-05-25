package xdsnew

import (
	"context"
	"fmt"
	"hash"
	"hash/fnv"
	"log/slog"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/envoy/xds"
	callbacks "github.com/cilium/cilium/pkg/envoy/xdsnew/callbacks"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	cilium "github.com/cilium/proxy/go/cilium/api"
	"github.com/davecgh/go-spew/spew"
	envoy_config_cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_config_tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	cache_types "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	cache "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	envoy_resource "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"k8s.io/apimachinery/pkg/util/rand"
)

const (
	// NetworkPolicyTypeURL is the type URL of NetworkPolicy resources.
	NetworkPolicyTypeURL      = "type.googleapis.com/cilium.NetworkPolicy"
	NetworkPolicyHostsTypeUrl = "type.googleapis.com/cilium.NetworkPolicyHosts"
)

type Cache interface {
	cache.SnapshotCache

	GetVersion(resources *xds.Resources) string
	GenerateSnapshot(resources *xds.Resources, logger *slog.Logger) (*WrappedSnapshot, error)
	UpdateSnapshot(ctx context.Context, nodeID string, newSnapshot WrappedSnapshot, wg *completion.WaitGroup, updatedTypeURLS map[string]struct{}, revertFunc func(), callback func(err error)) error
	SetResources(nodeID string, resources *xds.Resources)
	ClearSnapshotForType(nodeID string, resourceType envoy_resource.Type)
	GetAllResources(nodeID string) *xds.Resources
	AreDifferentSnapshots(left, right cache.ResourceSnapshot) bool
	GetCompletionCallbacks() *callbacks.CompletionCallbacks
}

type CacheImpl struct {
	// mutex protects accesses to the configuration resources below.
	mutex *lock.RWMutex
	// resourcesInSnapshot holds the last set of resources (keyed by nodeID) pushed to Envoy.
	resourcesInSnapshot map[string]*xds.Resources
	snapshotCache       cache.SnapshotCache
	npdsCache           *cache.LinearCache
	nphdsCache          *cache.LinearCache
	mux                 cache.MuxCache
	logger              *slog.Logger
	hasher              hash.Hash32
	completionCbs       callbacks.CompletionCallbacks
}

var _ Cache = &CacheImpl{}

// WrappedSnapshot wraps the go-control-plane Snapshot and adds Cilium custom
// resource types (NetworkPolicy, NetworkPolicyHosts) so that a single snapshot
// can be stored per node and still serve all resource types.
type WrappedSnapshot struct {
	*cache.Snapshot

	// NetworkPolicies stores cilium NetworkPolicy resources keyed by name.
	NetworkPolicies map[string]cache_types.Resource
	// networkPolicyVersion is the opaque version string for network policies.
	networkPolicyVersion string
}

// Ensure WrappedSnapshot implements cache.ResourceSnapshot.
var _ cache.ResourceSnapshot = &WrappedSnapshot{}

func NewWrappedSnapshot(snapshot *cache.Snapshot, networkPolicies map[string]cache_types.Resource, version string) *WrappedSnapshot {
	if networkPolicies == nil {
		networkPolicies = make(map[string]cache_types.Resource)
	}
	return &WrappedSnapshot{
		Snapshot:             snapshot,
		NetworkPolicies:      networkPolicies,
		networkPolicyVersion: version,
	}
}

func (w *WrappedSnapshot) GetVersion(typeURL string) string {
	if typeURL == NetworkPolicyTypeURL {
		return w.networkPolicyVersion
	}
	return w.Snapshot.GetVersion(typeURL)
}

func (w *WrappedSnapshot) GetResources(typeURL string) map[string]cache_types.Resource {
	if typeURL == NetworkPolicyTypeURL {
		return w.NetworkPolicies
	}
	return w.Snapshot.GetResources(typeURL)
}

func (w *WrappedSnapshot) GetResourcesAndTTL(typeURL string) map[string]cache_types.ResourceWithTTL {
	if typeURL == NetworkPolicyTypeURL {
		out := make(map[string]cache_types.ResourceWithTTL, len(w.NetworkPolicies))
		for k, v := range w.NetworkPolicies {
			out[k] = cache_types.ResourceWithTTL{Resource: v}
		}
		return out
	}
	return w.Snapshot.GetResourcesAndTTL(typeURL)
}

func (w *WrappedSnapshot) ConstructVersionMap() error {
	return w.Snapshot.ConstructVersionMap()
}

func (w *WrappedSnapshot) GetVersionMap(typeURL string) map[string]string {
	if typeURL == NetworkPolicyTypeURL {
		out := make(map[string]string, len(w.NetworkPolicies))
		for k := range w.NetworkPolicies {
			out[k] = w.networkPolicyVersion
		}
		return out
	}
	return w.Snapshot.GetVersionMap(typeURL)
}

func NewCache(logger *slog.Logger) *CacheImpl {
	snapshotCache := cache.NewSnapshotCache( /*ads*/ true, cache.IDHash{} /*logger*/, nil)
	npdsCache := cache.NewLinearCache(NetworkPolicyTypeURL)
	nphdsCache := cache.NewLinearCache(NetworkPolicyHostsTypeUrl)

	return &CacheImpl{
		snapshotCache: snapshotCache,
		npdsCache:     npdsCache,
		nphdsCache:    nphdsCache,
		mux: cache.MuxCache{
			Classify: func(req *cache.Request) string {
				switch req.TypeUrl {
				case NetworkPolicyTypeURL:
					return "npds"
				case NetworkPolicyHostsTypeUrl:
					return "nphds"
				default:
					return "default"
				}
			},
			ClassifyDelta: func(req *cache.DeltaRequest) string {
				switch req.TypeUrl {
				case NetworkPolicyTypeURL:
					return "npds"
				case NetworkPolicyHostsTypeUrl:
					return "nphds"
				default:
					return "default"
				}
			},
			Caches: map[string]cache.Cache{
				"npds":    npdsCache,
				"nphds":   nphdsCache,
				"default": snapshotCache,
			},
		},
		mutex:               &lock.RWMutex{},
		resourcesInSnapshot: make(map[string]*xds.Resources),
		logger:              logger,
		hasher:              fnv.New32a(),
		completionCbs:       callbacks.NewCompletionCallbacks(logger),
	}
}

func (c *CacheImpl) hash(resources map[string]string) string {
	c.hasher.Reset()
	printer := spew.ConfigState{
		Indent:         " ",
		SortKeys:       true,
		DisableMethods: true,
		SpewKeys:       true,
	}
	printer.Fprintf(c.hasher, "%#v", resources)
	return rand.SafeEncodeString(fmt.Sprint(c.hasher.Sum32()))
}

func (c *CacheImpl) GetVersion(resources *xds.Resources) string {
	encodedResources, err := Marshal(resources)
	if err != nil {
		c.logger.Error(fmt.Sprintf("failed to marshal resources for versioning: %v", err))
		return ""
	}
	return c.hash(encodedResources)
}

func (c *CacheImpl) GenerateSnapshot(resources *xds.Resources, logger *slog.Logger) (*WrappedSnapshot, error) {
	endpoints := make([]cache_types.Resource, 0, len(resources.Endpoints))
	clusters := make([]cache_types.Resource, 0, len(resources.Clusters))
	routes := make([]cache_types.Resource, 0, len(resources.Routes))
	listeners := make([]cache_types.Resource, 0, len(resources.Listeners))
	networkPolicies := make(map[string]cache_types.Resource, len(resources.NetworkPolicies))
	secrets := make([]cache_types.Resource, 0, len(resources.Secrets))

	for _, r := range resources.Endpoints {
		endpoints = append(endpoints, r)
	}
	for _, r := range resources.Clusters {
		clusters = append(clusters, r)
	}
	for _, r := range resources.Routes {
		routes = append(routes, r)
	}
	for _, r := range resources.Listeners {
		listeners = append(listeners, r)
	}
	for name, r := range resources.NetworkPolicies {
		networkPolicies[name] = r
	}
	for _, r := range resources.Secrets {
		secrets = append(secrets, r)
	}

	version := c.GetVersion(resources)

	snapshot, err := cache.NewSnapshot(version, map[envoy_resource.Type][]cache_types.Resource{
		envoy_resource.EndpointType: endpoints,
		envoy_resource.ClusterType:  clusters,
		envoy_resource.RouteType:    routes,
		envoy_resource.ListenerType: listeners,
		envoy_resource.SecretType:   secrets,
	})
	if err != nil {
		c.logger.Error("failed to generate snapshot: %q", logfields.Error, err)
		return nil, err
	}
	if err = snapshot.Consistent(); err != nil {
		c.logger.Warn(fmt.Sprintf("Snapshot inconsistency detected (non-fatal): %q", err))
	}
	wrappedSnapshot := NewWrappedSnapshot(snapshot, networkPolicies, version)
	return wrappedSnapshot, nil
}

func (c CacheImpl) GetSnapshot(nodeID string) (cache.ResourceSnapshot, error) {
	snap, err := c.snapshotCache.GetSnapshot(nodeID)
	if err != nil {
		return &cache.Snapshot{}, err
	}

	return snap, nil
}

func (c *CacheImpl) GetCompletionCallbacks() *callbacks.CompletionCallbacks {
	return &c.completionCbs
}

func (c CacheImpl) SetResources(nodeID string, resources *xds.Resources) {
	c.resourcesInSnapshot[nodeID] = resources
}

func (c CacheImpl) SetSnapshot(ctx context.Context, nodeID string, newSnapshot cache.ResourceSnapshot) error {
	return c.snapshotCache.SetSnapshot(ctx, nodeID, newSnapshot)
}

func (c CacheImpl) UpdateSnapshot(ctx context.Context, nodeID string, newSnapshot WrappedSnapshot, wg *completion.WaitGroup, updatedTypeURLS map[string]struct{}, revertFunc func(), callback func(err error)) error {
	addCompletion := func(wg *completion.WaitGroup, cb func(err error)) *completion.Completion {
		if cb != nil {
			return wg.AddCompletionWithCallback(nil, cb)
		}
		return wg.AddCompletion(nil)
	}

	var comp *completion.Completion
	if wg != nil && len(updatedTypeURLS) > 0 {
		for typeURL := range updatedTypeURLS {
			// Custom Cilium resource typed will be processed below once resource version has been computed by the linear cache.
			if typeURL != NetworkPolicyTypeURL && typeURL != NetworkPolicyHostsTypeUrl {
				comp = addCompletion(wg, callback)
				c.completionCbs.AddTypeVersionCompletion(comp, newSnapshot.GetVersion(typeURL), typeURL, nodeID, revertFunc)
			}
		}
	}
	err := c.snapshotCache.SetSnapshot(ctx, nodeID, newSnapshot.Snapshot)

	if err != nil && comp != nil {
		c.completionCbs.RemoveTypeVersionCompletion(comp)
	}

	if len(newSnapshot.NetworkPolicies) > 0 {
		err = c.npdsCache.UpdateResources(newSnapshot.NetworkPolicies, nil)
		if wg != nil {
			comp = addCompletion(wg, callback)
			// todo (nezdolik) Currenltly is not possible to get resource version from linear cache, instead version will be updated in OnStreamResponse callback.
			// https://github.com/envoyproxy/go-control-plane/pull/1467
			c.completionCbs.AddTypeVersionCompletion(comp, "", NetworkPolicyTypeURL, nodeID, revertFunc)
		}
	}

	return err
}

func (c CacheImpl) ClearSnapshot(nodeID string) {
	c.snapshotCache.ClearSnapshot(nodeID)
	c.resourcesInSnapshot[nodeID] = &xds.Resources{}
}

func (c CacheImpl) ClearSnapshotForType(nodeID string, resourceType envoy_resource.Type) {
	resources, exists := c.resourcesInSnapshot[nodeID]
	if !exists {
		c.logger.Warn(fmt.Sprintf("No resources found for node %s when clearing snapshot for resource type %s", nodeID, resourceType))
		return
	}
	switch resourceType {
	case envoy_resource.EndpointType:
		resources.Endpoints = map[string]*envoy_config_endpoint.ClusterLoadAssignment{}
	case envoy_resource.ClusterType:
		resources.Clusters = map[string]*envoy_config_cluster.Cluster{}
	case envoy_resource.RouteType:
		resources.Routes = map[string]*envoy_config_route.RouteConfiguration{}
	case envoy_resource.ListenerType:
		resources.Listeners = map[string]*envoy_config_listener.Listener{}
	case envoy_resource.SecretType:
		resources.Secrets = map[string]*envoy_config_tls.Secret{}
	case NetworkPolicyTypeURL:
		resources.NetworkPolicies = map[string]*cilium.NetworkPolicy{}
	default:
		c.logger.Warn(fmt.Sprintf("Clearing snapshot for resource type %s is not supported", resourceType))
	}
	newSnapshot, err := c.GenerateSnapshot(resources, c.logger)
	if err != nil {
		c.logger.Error(fmt.Sprintf("Failed to generate snapshot after clearing resources of type %s for node %s: %v", resourceType, nodeID, err))
		return
	}
	if err = c.SetSnapshot(context.Background(), nodeID, newSnapshot); err != nil {
		c.logger.Error(fmt.Sprintf("Failed to set snapshot after clearing resources of type %s for node %s: %v", resourceType, nodeID, err))
		return
	}
}

func (c CacheImpl) CreateDeltaWatch(*cache.DeltaRequest, cache.Subscription, chan cache.DeltaResponse) (cancel func(), err error) {
	panic("unimplemented")
}

func (c CacheImpl) CreateWatch(request *cache.Request, sub cache.Subscription, respChan chan cache.Response) (cancel func(), err error) {
	return c.mux.CreateWatch(request, sub, respChan)
}

// Fetch implements cache.SnapshotCache.
func (c CacheImpl) Fetch(context context.Context, request *cache.Request) (cache.Response, error) {
	return c.mux.Fetch(context, request)
}

// GetStatusInfo implements cache.SnapshotCache.
func (c CacheImpl) GetStatusInfo(node string) cache.StatusInfo {
	return c.snapshotCache.GetStatusInfo(node)
}

func (c CacheImpl) GetAllResources(nodeID string) *xds.Resources {
	return c.resourcesInSnapshot[nodeID]
}

// GetStatusKeys implements cache.SnapshotCache.
func (c CacheImpl) GetStatusKeys() []string {
	return c.snapshotCache.GetStatusKeys()
}

// todo(nezdolik) switch to wrappedsnapshot
func (c CacheImpl) AreDifferentSnapshots(left, right cache.ResourceSnapshot) bool {
	for _, resourceType := range []envoy_resource.Type{
		envoy_resource.EndpointType, envoy_resource.ClusterType, envoy_resource.RouteType,
		envoy_resource.ListenerType, envoy_resource.SecretType,
	} {
		if left.GetVersion(resourceType) != right.GetVersion(resourceType) {
			return true
		}
	}
	return false
}
