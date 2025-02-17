// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"context"
	"fmt"

	cilium "github.com/cilium/proxy/go/cilium/api"
	envoy_config_cluster "github.com/cilium/proxy/go/envoy/config/cluster/v3"
	envoy_config_core "github.com/cilium/proxy/go/envoy/config/core/v3"
	envoy_config_endpoint "github.com/cilium/proxy/go/envoy/config/endpoint/v3"
	envoy_config_listener "github.com/cilium/proxy/go/envoy/config/listener/v3"
	envoy_config_route "github.com/cilium/proxy/go/envoy/config/route/v3"
	envoy_config_http "github.com/cilium/proxy/go/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_config_tcp "github.com/cilium/proxy/go/envoy/extensions/filters/network/tcp_proxy/v3"
	envoy_config_tls "github.com/cilium/proxy/go/envoy/extensions/transport_sockets/tls/v3"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cilium/cilium/pkg/completion"
	_ "github.com/cilium/cilium/pkg/envoy/resource"
	"github.com/cilium/cilium/pkg/envoy/xds"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/time"
)

// Resources contains all Envoy resources parsed from a CiliumEnvoyConfig CRD
type Resources struct {
	Listeners []*envoy_config_listener.Listener
	Secrets   []*envoy_config_tls.Secret
	Routes    []*envoy_config_route.RouteConfiguration
	Clusters  []*envoy_config_cluster.Cluster
	Endpoints []*envoy_config_endpoint.ClusterLoadAssignment

	// Callback functions that are called if the corresponding Listener change was successfully acked by Envoy
	portAllocationCallbacks map[string]func(context.Context) error
}

type PortAllocator interface {
	AllocateProxyPort(name string, ingress, localOnly bool) (uint16, error)
	AckProxyPort(ctx context.Context, name string) error
	ReleaseProxyPort(name string) error
}

// ListenersAddedOrDeleted returns 'true' if a listener is added or removed when updating from 'old'
// to 'new'
func (old *Resources) ListenersAddedOrDeleted(new *Resources) bool {
	// Typically the number of listeners in a CEC is small (e.g, one), so it should be OK to
	// scan the slices like here
	for _, nl := range new.Listeners {
		found := false
		for _, ol := range old.Listeners {
			if ol.Name == nl.Name {
				found = true
				break
			}
		}
		if !found {
			return true // a listener was added
		}
	}
	for _, ol := range old.Listeners {
		found := false
		for _, nl := range new.Listeners {
			if nl.Name == ol.Name {
				found = true
				break
			}
		}
		if !found {
			return true // a listener was removed
		}
	}
	return false
}

func qualifyTcpProxyResourceNames(namespace, name string, tcpProxy *envoy_config_tcp.TcpProxy) (updated bool) {
	switch c := tcpProxy.GetClusterSpecifier().(type) {
	case *envoy_config_tcp.TcpProxy_Cluster:
		if c != nil {
			c.Cluster, updated = api.ResourceQualifiedName(namespace, name, c.Cluster)
		}
	case *envoy_config_tcp.TcpProxy_WeightedClusters:
		if c != nil {
			for _, wc := range c.WeightedClusters.Clusters {
				var nameUpdated bool
				wc.Name, nameUpdated = api.ResourceQualifiedName(namespace, name, wc.Name)
				if nameUpdated {
					updated = true
				}
			}
		}
	}
	return updated
}

func qualifyRouteConfigurationResourceNames(namespace, name string, routeConfig *envoy_config_route.RouteConfiguration) (updated bool) {
	// Strictly not a reference, and may be an empty string
	routeConfig.Name, updated = api.ResourceQualifiedName(namespace, name, routeConfig.Name, api.ForceNamespace)

	for _, vhost := range routeConfig.VirtualHosts {
		var nameUpdated bool
		vhost.Name, nameUpdated = api.ResourceQualifiedName(namespace, name, vhost.Name, api.ForceNamespace)
		if nameUpdated {
			updated = true
		}
		for _, rt := range vhost.Routes {
			if action := rt.GetRoute(); action != nil {
				if clusterName := action.GetCluster(); clusterName != "" {
					action.GetClusterSpecifier().(*envoy_config_route.RouteAction_Cluster).Cluster, nameUpdated = api.ResourceQualifiedName(namespace, name, clusterName)
					if nameUpdated {
						updated = true
					}
				}
				for _, r := range action.GetRequestMirrorPolicies() {
					if clusterName := r.GetCluster(); clusterName != "" {
						r.Cluster, nameUpdated = api.ResourceQualifiedName(namespace, name, clusterName)
						if nameUpdated {
							updated = true
						}
					}
				}
				if weightedClusters := action.GetWeightedClusters(); weightedClusters != nil {
					for _, cluster := range weightedClusters.GetClusters() {
						cluster.Name, nameUpdated = api.ResourceQualifiedName(namespace, name, cluster.Name)
						if nameUpdated {
							updated = true
						}
					}
				}
			}
		}
	}
	return updated
}

// ParseResources parses all supported Envoy resource types from CiliumEnvoyConfig CRD to Resources
// type cecNamespace and cecName parameters, if not empty, will be prepended to the Envoy resource
// names.
// Parameter `newResources` is passed as `true` when parsing resources that are being added or are the new version of the resources being updated,
// and as `false` if the resources are being removed or are the old version of the resources being updated.
func ParseResources(cecNamespace string, cecName string, anySlice []cilium_v2.XDSResource, validate bool, portAllocator PortAllocator, isL7LB bool, useOriginalSourceAddr bool, newResources bool) (Resources, error) {
	resources := Resources{}
	for _, r := range anySlice {
		// Skip empty TypeURLs, which are left behind when Unmarshaling resource JSON fails
		if r.TypeUrl == "" {
			continue
		}
		message, err := r.UnmarshalNew()
		if err != nil {
			return Resources{}, err
		}
		typeURL := r.GetTypeUrl()
		switch typeURL {
		case ListenerTypeURL:
			listener, ok := message.(*envoy_config_listener.Listener)
			if !ok {
				return Resources{}, fmt.Errorf("Invalid type for Listener: %T", message)
			}
			// Check that a listener name is provided and that it is unique within this CEC
			if listener.Name == "" {
				return Resources{}, fmt.Errorf("'Listener name not provided")
			}
			for i := range resources.Listeners {
				if listener.Name == resources.Listeners[i].Name {
					return Resources{}, fmt.Errorf("Duplicate Listener name %q", listener.Name)
				}
			}

			if option.Config.EnableBPFTProxy {
				// Envoy since 1.20.0 uses SO_REUSEPORT on listeners by default.
				// BPF TPROXY is currently not compatible with SO_REUSEPORT, so
				// disable it.  Note that this may degrade Envoy performance.
				listener.EnableReusePort = &wrapperspb.BoolValue{Value: false}
			}

			// Figure out if this is an internal listener
			isInternalListener := listener.GetInternalListener() != nil

			// Only inject Cilium filters if Cilium allocates listener address
			injectCiliumFilters := listener.GetAddress() == nil && !isInternalListener

			// Inject Cilium bpf metadata listener filter, if not already present.
			if !isInternalListener {
				found := false
				for _, lf := range listener.ListenerFilters {
					if lf.Name == "cilium.bpf_metadata" {
						found = true
						break
					}
				}
				if !found {
					listener.ListenerFilters = append(listener.ListenerFilters, getListenerFilter(false /* egress */, useOriginalSourceAddr, isL7LB))
				}
			}

			// Fill in SDS & RDS config source if unset
			for _, fc := range listener.FilterChains {
				fillInTransportSocketXDS(cecNamespace, cecName, fc.TransportSocket)
				foundCiliumNetworkFilter := false
				for i, filter := range fc.Filters {
					if filter.Name == "cilium.network" {
						foundCiliumNetworkFilter = true
					}
					tc := filter.GetTypedConfig()
					if tc == nil {
						continue
					}
					switch tc.GetTypeUrl() {
					case HttpConnectionManagerTypeURL:
						any, err := tc.UnmarshalNew()
						if err != nil {
							continue
						}
						hcmConfig, ok := any.(*envoy_config_http.HttpConnectionManager)
						if !ok {
							continue
						}
						updated := false
						if rds := hcmConfig.GetRds(); rds != nil {
							// Since we are prepending CEC namespace and name to Routes name,
							// we must do the same here to point to the correct Route resource.
							if rds.RouteConfigName != "" {
								rds.RouteConfigName, updated = api.ResourceQualifiedName(cecNamespace, cecName, rds.RouteConfigName, api.ForceNamespace)
							}
							if rds.ConfigSource == nil {
								rds.ConfigSource = ciliumXDS
								updated = true
							}
						}
						if routeConfig := hcmConfig.GetRouteConfig(); routeConfig != nil {
							if qualifyRouteConfigurationResourceNames(cecNamespace, cecName, routeConfig) {
								updated = true
							}
						}
						if injectCiliumFilters {
							l7FilterUpdated := injectCiliumL7Filter(hcmConfig)
							updated = updated || l7FilterUpdated
						}
						if updated {
							filter.ConfigType = &envoy_config_listener.Filter_TypedConfig{
								TypedConfig: toAny(hcmConfig),
							}
						}
					case TCPProxyTypeURL:
						any, err := tc.UnmarshalNew()
						if err != nil {
							continue
						}
						tcpProxy, ok := any.(*envoy_config_tcp.TcpProxy)
						if !ok {
							continue
						}

						if qualifyTcpProxyResourceNames(cecNamespace, cecName, tcpProxy) {
							filter.ConfigType = &envoy_config_listener.Filter_TypedConfig{
								TypedConfig: toAny(tcpProxy),
							}
						}
					default:
						continue
					}
					if injectCiliumFilters {
						if !foundCiliumNetworkFilter {
							// Inject Cilium network filter just before the HTTP Connection Manager or TCPProxy filter
							fc.Filters = append(fc.Filters[:i+1], fc.Filters[i:]...)
							fc.Filters[i] = &envoy_config_listener.Filter{
								Name: "cilium.network",
								ConfigType: &envoy_config_listener.Filter_TypedConfig{
									TypedConfig: toAny(&cilium.NetworkFilter{}),
								},
							}
						}
					}
					break // Done with this filter chain
				}
			}

			name := listener.Name
			listener.Name, _ = api.ResourceQualifiedName(cecNamespace, cecName, listener.Name, api.ForceNamespace)

			if validate {
				if err := listener.Validate(); err != nil {
					return Resources{}, fmt.Errorf("ParseResources: Could not validate Listener (%s): %s", err, listener.String())
				}
			}
			resources.Listeners = append(resources.Listeners, listener)

			log.Debugf("ParseResources: Parsed listener %q: %v", name, listener)

		case RouteTypeURL:
			route, ok := message.(*envoy_config_route.RouteConfiguration)
			if !ok {
				return Resources{}, fmt.Errorf("Invalid type for Route: %T", message)
			}
			// Check that a Route name is provided and that it is unique within this CEC
			if route.Name == "" {
				return Resources{}, fmt.Errorf("RouteConfiguration name not provided")
			}
			for i := range resources.Routes {
				if route.Name == resources.Routes[i].Name {
					return Resources{}, fmt.Errorf("Duplicate Route name %q", route.Name)
				}
			}

			qualifyRouteConfigurationResourceNames(cecNamespace, cecName, route)

			name := route.Name
			route.Name, _ = api.ResourceQualifiedName(cecNamespace, cecName, name, api.ForceNamespace)

			if validate {
				if err := route.Validate(); err != nil {
					return Resources{}, fmt.Errorf("ParseResources: Could not validate RouteConfiguration (%s): %s", err, route.String())
				}
			}
			resources.Routes = append(resources.Routes, route)

			log.Debugf("ParseResources: Parsed route %q: %v", name, route)

		case ClusterTypeURL:
			cluster, ok := message.(*envoy_config_cluster.Cluster)
			if !ok {
				return Resources{}, fmt.Errorf("Invalid type for Route: %T", message)
			}
			// Check that a Cluster name is provided and that it is unique within this CEC
			if cluster.Name == "" {
				return Resources{}, fmt.Errorf("Cluster name not provided")
			}
			for i := range resources.Clusters {
				if cluster.Name == resources.Clusters[i].Name {
					return Resources{}, fmt.Errorf("Duplicate Cluster name %q", cluster.Name)
				}
			}

			fillInTransportSocketXDS(cecNamespace, cecName, cluster.TransportSocket)

			// Fill in EDS config source if unset
			if enum := cluster.GetType(); enum == envoy_config_cluster.Cluster_EDS {
				if cluster.EdsClusterConfig == nil {
					cluster.EdsClusterConfig = &envoy_config_cluster.Cluster_EdsClusterConfig{}
				}
				if cluster.EdsClusterConfig.EdsConfig == nil {
					cluster.EdsClusterConfig.EdsConfig = ciliumXDS
				}
			}

			if cluster.LoadAssignment != nil {
				cluster.LoadAssignment.ClusterName, _ = api.ResourceQualifiedName(cecNamespace, cecName, cluster.LoadAssignment.ClusterName)
			}

			name := cluster.Name
			cluster.Name, _ = api.ResourceQualifiedName(cecNamespace, cecName, name)

			if validate {
				if err := cluster.Validate(); err != nil {
					return Resources{}, fmt.Errorf("ParseResources: Could not validate Cluster %q (%s): %s", cluster.Name, err, cluster.String())
				}
			}
			resources.Clusters = append(resources.Clusters, cluster)

			log.Debugf("ParseResources: Parsed cluster %q: %v", name, cluster)

		case EndpointTypeURL:
			endpoints, ok := message.(*envoy_config_endpoint.ClusterLoadAssignment)
			if !ok {
				return Resources{}, fmt.Errorf("Invalid type for Route: %T", message)
			}
			// Check that a Cluster name is provided and that it is unique within this CEC
			if endpoints.ClusterName == "" {
				return Resources{}, fmt.Errorf("ClusterLoadAssignment cluster_name not provided")
			}
			for i := range resources.Endpoints {
				if endpoints.ClusterName == resources.Endpoints[i].ClusterName {
					return Resources{}, fmt.Errorf("Duplicate cluster_name %q", endpoints.ClusterName)
				}
			}

			name := endpoints.ClusterName
			endpoints.ClusterName, _ = api.ResourceQualifiedName(cecNamespace, cecName, name)

			if validate {
				if err := endpoints.Validate(); err != nil {
					return Resources{}, fmt.Errorf("ParseResources: Could not validate ClusterLoadAssignment for cluster %q (%s): %s", endpoints.ClusterName, err, endpoints.String())
				}
			}
			resources.Endpoints = append(resources.Endpoints, endpoints)

			log.Debugf("ParseResources: Parsed endpoints for cluster %q: %v", name, endpoints)

		case SecretTypeURL:
			secret, ok := message.(*envoy_config_tls.Secret)
			if !ok {
				return Resources{}, fmt.Errorf("Invalid type for Secret: %T", message)
			}
			// Check that a Secret name is provided and that it is unique within this CEC
			if secret.Name == "" {
				return Resources{}, fmt.Errorf("Secret name not provided")
			}
			for i := range resources.Secrets {
				if secret.Name == resources.Secrets[i].Name {
					return Resources{}, fmt.Errorf("Duplicate Secret name %q", secret.Name)
				}
			}

			name := secret.Name
			secret.Name, _ = api.ResourceQualifiedName(cecNamespace, cecName, name)

			if validate {
				if err := secret.Validate(); err != nil {
					return Resources{}, fmt.Errorf("ParseResources: Could not validate Secret for cluster %q (%s)", secret.Name, err)
				}
			}
			resources.Secrets = append(resources.Secrets, secret)

			log.Debugf("ParseResources: Parsed secret: %s", name)

		default:
			return Resources{}, fmt.Errorf("Unsupported type: %s", typeURL)
		}
	}

	// Allocate TPROXY ports for listeners without address.
	// Do this only after all other possible error cases.
	for _, listener := range resources.Listeners {
		// Figure out if this is an internal listener
		isInternalListener := listener.GetInternalListener() != nil

		if listener.GetAddress() == nil && !isInternalListener {
			listenerName := listener.Name
			port, err := portAllocator.AllocateProxyPort(listenerName, false, true)
			if err != nil || port == 0 {
				return Resources{}, fmt.Errorf("listener port allocation for %q failed: %s", listenerName, err)
			}
			if resources.portAllocationCallbacks == nil {
				resources.portAllocationCallbacks = make(map[string]func(context.Context) error)
			}
			if newResources {
				resources.portAllocationCallbacks[listenerName] = func(ctx context.Context) error { return portAllocator.AckProxyPort(ctx, listenerName) }
			} else {
				resources.portAllocationCallbacks[listenerName] = func(_ context.Context) error { return portAllocator.ReleaseProxyPort(listenerName) }
			}

			listener.Address, listener.AdditionalAddresses = getLocalListenerAddresses(port, option.Config.IPv4Enabled(), option.Config.IPv6Enabled())
		}
		if validate {
			if err := listener.Validate(); err != nil {
				return Resources{}, fmt.Errorf("ParseResources: Could not validate Listener %q (%s): %s", listener.Name, err, listener.String())
			}
		}
	}

	return resources, nil
}

// injectCiliumL7Filter injects the Cilium HTTP filter just before the HTTP Router filter
func injectCiliumL7Filter(hcmConfig *envoy_config_http.HttpConnectionManager) bool {
	foundCiliumL7Filter := false

	for j, httpFilter := range hcmConfig.HttpFilters {
		switch httpFilter.Name {
		case "cilium.l7policy":
			foundCiliumL7Filter = true
		case "envoy.filters.http.router":
			if !foundCiliumL7Filter {
				hcmConfig.HttpFilters = append(hcmConfig.HttpFilters[:j+1], hcmConfig.HttpFilters[j:]...)
				hcmConfig.HttpFilters[j] = getCiliumHttpFilter()
				return true
			}
		}
	}

	return false
}

func (s *xdsServer) UpsertEnvoyResources(ctx context.Context, resources Resources) error {
	if option.Config.Debug {
		msg := ""
		sep := ""
		if len(resources.Listeners) > 0 {
			msg += fmt.Sprintf("%d listeners", len(resources.Listeners))
			sep = ", "
		}
		if len(resources.Routes) > 0 {
			msg += fmt.Sprintf("%s%d routes", sep, len(resources.Routes))
			sep = ", "
		}
		if len(resources.Clusters) > 0 {
			msg += fmt.Sprintf("%s%d clusters", sep, len(resources.Clusters))
			sep = ", "
		}
		if len(resources.Endpoints) > 0 {
			msg += fmt.Sprintf("%s%d endpoints", sep, len(resources.Endpoints))
			sep = ", "
		}
		if len(resources.Secrets) > 0 {
			msg += fmt.Sprintf("%s%d secrets", sep, len(resources.Secrets))
		}

		log.Debugf("UpsertEnvoyResources: Upserting %s...", msg)
	}
	var wg *completion.WaitGroup
	// Listener config may fail if it refers to a cluster that has not been added yet, so we
	// must wait for Envoy to ACK cluster config before adding Listeners to be sure Listener
	// config does not fail for this reason.
	// Enable wait before new Listeners are added if clusters are also added.
	if len(resources.Listeners) > 0 && len(resources.Clusters) > 0 {
		wg = completion.NewWaitGroup(ctx)
	}
	var revertFuncs xds.AckingResourceMutatorRevertFuncList
	// Do not wait for the addition of routes, clusters, endpoints, routes,
	// or secrets as there are no guarantees that these additions will be
	// acked. For example, if the listener referring to was already deleted
	// earlier, there are no references to the deleted resources anymore,
	// in which case we could wait forever for the ACKs. This could also
	// happen if there is no listener referring to these named
	// resources to begin with.
	// If both listeners and clusters are added then wait for clusters.
	for _, r := range resources.Secrets {
		log.Debugf("Envoy upsertSecret %s", r.Name)
		revertFuncs = append(revertFuncs, s.upsertSecret(r.Name, r, nil, nil))
	}
	for _, r := range resources.Endpoints {
		log.Debugf("Envoy upsertEndpoint %s %v", r.ClusterName, r)
		revertFuncs = append(revertFuncs, s.upsertEndpoint(r.ClusterName, r, nil, nil))
	}
	for _, r := range resources.Clusters {
		log.Debugf("Envoy upsertCluster %s %v", r.Name, r)
		revertFuncs = append(revertFuncs, s.upsertCluster(r.Name, r, wg, nil))
	}
	for _, r := range resources.Routes {
		log.Debugf("Envoy upsertRoute %s %v", r.Name, r)
		revertFuncs = append(revertFuncs, s.upsertRoute(r.Name, r, nil, nil))
	}
	// Wait before new Listeners are added if clusters were also added above.
	if wg != nil {
		start := time.Now()
		log.Debug("UpsertEnvoyResources: Waiting for cluster updates to complete...")
		err := wg.Wait()
		log.Debugf("UpsertEnvoyResources: Wait time for cluster updates %v (err: %s)", time.Since(start), err)

		// revert all changes in case of failure
		if err != nil {
			revertFuncs.Revert(nil)
			log.Debug("UpsertEnvoyResources: Finished reverting failed xDS transactions")
			return err
		}
		wg = nil
	}
	// Wait only if new Listeners are added, as they will always be acked.
	// (unreferenced routes or endpoints (and maybe clusters) are not ACKed or NACKed).
	if len(resources.Listeners) > 0 {
		wg = completion.NewWaitGroup(ctx)
	}
	for _, r := range resources.Listeners {
		log.Debugf("Envoy upsertListener %s %v", r.Name, r)
		listenerName := r.Name
		revertFuncs = append(revertFuncs, s.upsertListener(r.Name, r, wg,
			// this callback is not called if there is no change
			func(err error) {
				if err == nil && resources.portAllocationCallbacks[listenerName] != nil {
					if callbackErr := resources.portAllocationCallbacks[listenerName](ctx); callbackErr != nil {
						log.WithError(callbackErr).Warn("Failure in port allocation callback")
					}
				}
			}))
	}
	if wg != nil {
		start := time.Now()
		log.Debug("UpsertEnvoyResources: Waiting for proxy updates to complete...")
		err := wg.Wait()
		log.Debugf("UpsertEnvoyResources: Wait time for proxy updates %v (err: %s)", time.Since(start), err)

		// revert all changes in case of failure
		if err != nil {
			revertFuncs.Revert(nil)
			log.Debug("UpsertEnvoyResources: Finished reverting failed xDS transactions")
		}
		return err
	}
	return nil
}

func (s *xdsServer) UpdateEnvoyResources(ctx context.Context, old, new Resources) error {
	waitForDelete := false
	var wg *completion.WaitGroup
	var revertFuncs xds.AckingResourceMutatorRevertFuncList
	// Wait only if new Listeners are added, as they will always be acked.
	// (unreferenced routes or endpoints (and maybe clusters) are not ACKed or NACKed).
	if len(new.Listeners) > 0 {
		wg = completion.NewWaitGroup(ctx)
	}
	// Delete old listeners not added in 'new' or if old and new listener have different ports
	var deleteListeners []*envoy_config_listener.Listener
	for _, oldListener := range old.Listeners {
		found := false
		port := uint32(0)
		if addr := oldListener.Address.GetSocketAddress(); addr != nil {
			port = addr.GetPortValue()
		}
		for _, newListener := range new.Listeners {
			if newListener.Name == oldListener.Name {
				if addr := newListener.Address.GetSocketAddress(); addr != nil && addr.GetPortValue() != port {
					log.Debugf("UpdateEnvoyResources: %s port changing from %d to %d...", newListener.Name, port, addr.GetPortValue())
					waitForDelete = true
				} else {
					// port is not changing, remove from new.PortAllocations to prevent acking an already acked port.
					delete(new.portAllocationCallbacks, newListener.Name)
					found = true
				}
				break
			}
		}
		if !found {
			deleteListeners = append(deleteListeners, oldListener)
		}
	}
	log.Debugf("UpdateEnvoyResources: Deleting %d, Upserting %d listeners...", len(deleteListeners), len(new.Listeners))
	for _, listener := range deleteListeners {
		listenerName := listener.Name
		revertFuncs = append(revertFuncs, s.deleteListener(listener.Name, wg,
			func(err error) {
				if err == nil && old.portAllocationCallbacks[listenerName] != nil {
					if callbackErr := old.portAllocationCallbacks[listenerName](ctx); callbackErr != nil {
						log.WithError(callbackErr).Warn("Failure in port allocation callback")
					}
				}
			}))
	}

	// Do not wait for the deletion of routes, clusters, endpoints, or
	// secrets as there are no quarantees that these deletions will be
	// acked. For example, if the listener referring to was already deleted
	// earlier, there are no references to the deleted resources any more,
	// in which case we could wait forever for the ACKs. This could also
	// happen if there is no listener referring to these other named
	// resources to begin with.

	// Delete old routes not added in 'new'
	var deleteRoutes []*envoy_config_route.RouteConfiguration
	for _, oldRoute := range old.Routes {
		found := false
		for _, newRoute := range new.Routes {
			if newRoute.Name == oldRoute.Name {
				found = true
			}
		}
		if !found {
			deleteRoutes = append(deleteRoutes, oldRoute)
		}
	}
	log.Debugf("UpdateEnvoyResources: Deleting %d, Upserting %d routes...", len(deleteRoutes), len(new.Routes))
	for _, route := range deleteRoutes {
		revertFuncs = append(revertFuncs, s.deleteRoute(route.Name, nil, nil))
	}

	// Delete old clusters not added in 'new'
	var deleteClusters []*envoy_config_cluster.Cluster
	for _, oldCluster := range old.Clusters {
		found := false
		for _, newCluster := range new.Clusters {
			if newCluster.Name == oldCluster.Name {
				found = true
			}
		}
		if !found {
			deleteClusters = append(deleteClusters, oldCluster)
		}
	}
	log.Debugf("UpdateEnvoyResources: Deleting %d, Upserting %d clusters...", len(deleteClusters), len(new.Clusters))
	for _, cluster := range deleteClusters {
		revertFuncs = append(revertFuncs, s.deleteCluster(cluster.Name, nil, nil))
	}

	// Delete old endpoints not added in 'new'
	var deleteEndpoints []*envoy_config_endpoint.ClusterLoadAssignment
	for _, oldEndpoint := range old.Endpoints {
		found := false
		for _, newEndpoint := range new.Endpoints {
			if newEndpoint.ClusterName == oldEndpoint.ClusterName {
				found = true
			}
		}
		if !found {
			deleteEndpoints = append(deleteEndpoints, oldEndpoint)
		}
	}
	log.Debugf("UpdateEnvoyResources: Deleting %d, Upserting %d endpoints...", len(deleteEndpoints), len(new.Endpoints))
	for _, endpoint := range deleteEndpoints {
		revertFuncs = append(revertFuncs, s.deleteEndpoint(endpoint.ClusterName, nil, nil))
	}

	// Delete old secrets not added in 'new'
	var deleteSecrets []*envoy_config_tls.Secret
	for _, oldSecret := range old.Secrets {
		found := false
		for _, newSecret := range new.Secrets {
			if newSecret.Name == oldSecret.Name {
				found = true
			}
		}
		if !found {
			deleteSecrets = append(deleteSecrets, oldSecret)
		}
	}
	log.Debugf("UpdateEnvoyResources: Deleting %d, Upserting %d secrets...", len(deleteSecrets), len(new.Secrets))
	for _, secret := range deleteSecrets {
		revertFuncs = append(revertFuncs, s.deleteSecret(secret.Name, nil, nil))
	}

	// Have to wait for deletes to complete before adding new listeners if a listener's port number is changed.
	if wg != nil && waitForDelete {
		start := time.Now()
		log.Debug("UpdateEnvoyResources: Waiting for proxy deletes to complete...")
		err := wg.Wait()
		if err != nil {
			log.Debug("UpdateEnvoyResources: delete failed: ", err)
		}
		log.Debug("UpdateEnvoyResources: Wait time for proxy deletes: ", time.Since(start))
		// new wait group for adds
		wg = completion.NewWaitGroup(ctx)
	}

	// Add new Secrets
	for _, r := range new.Secrets {
		revertFuncs = append(revertFuncs, s.upsertSecret(r.Name, r, nil, nil))
	}
	// Add new Endpoints
	for _, r := range new.Endpoints {
		revertFuncs = append(revertFuncs, s.upsertEndpoint(r.ClusterName, r, nil, nil))
	}
	// Add new Clusters
	for _, r := range new.Clusters {
		revertFuncs = append(revertFuncs, s.upsertCluster(r.Name, r, wg, nil))
	}
	// Add new Routes
	for _, r := range new.Routes {
		revertFuncs = append(revertFuncs, s.upsertRoute(r.Name, r, nil, nil))
	}
	if wg != nil && len(new.Clusters) > 0 {
		start := time.Now()
		log.Debug("UpdateEnvoyResources: Waiting for cluster updates to complete...")
		err := wg.Wait()
		if err != nil {
			log.Debug("UpdateEnvoyResources: cluster update failed: ", err)
		}
		log.Debug("UpdateEnvoyResources: Wait time for cluster updates: ", time.Since(start))
		// new wait group for adds
		wg = completion.NewWaitGroup(ctx)
	}
	// Add new Listeners
	for _, r := range new.Listeners {
		listenerName := r.Name
		revertFuncs = append(revertFuncs, s.upsertListener(r.Name, r, wg,
			// this callback is not called if there is no change
			func(err error) {
				if err == nil && new.portAllocationCallbacks[listenerName] != nil {
					if callbackErr := new.portAllocationCallbacks[listenerName](ctx); callbackErr != nil {
						log.WithError(callbackErr).Warn("Failure in port allocation callback")
					}
				}
			}))
	}

	if wg != nil {
		start := time.Now()
		log.Debug("UpdateEnvoyResources: Waiting for proxy updates to complete...")
		err := wg.Wait()
		log.Debugf("UpdateEnvoyResources: Wait time for proxy updates %v (err: %s)", time.Since(start), err)

		// revert all changes in case of failure
		if err != nil {
			revertFuncs.Revert(nil)
			log.Debug("UpdateEnvoyResources: Finished reverting failed xDS transactions")
		}
		return err
	}
	return nil
}

func (s *xdsServer) DeleteEnvoyResources(ctx context.Context, resources Resources) error {
	log.Debugf("DeleteEnvoyResources: Deleting %d listeners, %d routes, %d clusters, %d endpoints, and %d secrets...",
		len(resources.Listeners), len(resources.Routes), len(resources.Clusters), len(resources.Endpoints), len(resources.Secrets))
	var wg *completion.WaitGroup
	var revertFuncs xds.AckingResourceMutatorRevertFuncList
	// Wait only if new Listeners are added, as they will always be acked.
	// (unreferenced routes or endpoints (and maybe clusters) are not ACKed or NACKed).
	if len(resources.Listeners) > 0 {
		wg = completion.NewWaitGroup(ctx)
	}
	for _, r := range resources.Listeners {
		listenerName := r.Name
		revertFuncs = append(revertFuncs, s.deleteListener(r.Name, wg,
			func(err error) {
				if err == nil && resources.portAllocationCallbacks[listenerName] != nil {
					if callbackErr := resources.portAllocationCallbacks[listenerName](ctx); callbackErr != nil {
						log.WithError(callbackErr).Warn("Failure in port allocation callback")
					}
				}
			}))
	}

	// Do not wait for the deletion of routes, clusters, or endpoints, as
	// there are no guarantees that these deletions will be acked. For
	// example, if the listener referring to was already deleted earlier,
	// there are no references to the deleted resources anymore, in which
	// case we could wait forever for the ACKs. This could also happen if
	// there is no listener referring to other named resources to
	// begin with.
	for _, r := range resources.Routes {
		revertFuncs = append(revertFuncs, s.deleteRoute(r.Name, nil, nil))
	}
	for _, r := range resources.Clusters {
		revertFuncs = append(revertFuncs, s.deleteCluster(r.Name, nil, nil))
	}
	for _, r := range resources.Endpoints {
		revertFuncs = append(revertFuncs, s.deleteEndpoint(r.ClusterName, nil, nil))
	}
	for _, r := range resources.Secrets {
		revertFuncs = append(revertFuncs, s.deleteSecret(r.Name, nil, nil))
	}

	if wg != nil {
		start := time.Now()
		log.Debug("DeleteEnvoyResources: Waiting for proxy updates to complete...")
		err := wg.Wait()
		log.Debugf("DeleteEnvoyResources: Wait time for proxy updates %v (err: %s)", time.Since(start), err)

		// revert all changes in case of failure
		if err != nil {
			revertFuncs.Revert(nil)
			log.Debug("DeleteEnvoyResources: Finished reverting failed xDS transactions")
		}
		return err
	}
	return nil
}

func fillInTlsContextXDS(cecNamespace string, cecName string, tls *envoy_config_tls.CommonTlsContext) (updated bool) {
	qualify := func(sc *envoy_config_tls.SdsSecretConfig) {
		if sc.SdsConfig == nil {
			sc.SdsConfig = ciliumXDS
			updated = true
		}
		var nameUpdated bool
		sc.Name, nameUpdated = api.ResourceQualifiedName(cecNamespace, cecName, sc.Name)
		if nameUpdated {
			updated = true
		}
	}

	if tls != nil {
		for _, sc := range tls.TlsCertificateSdsSecretConfigs {
			qualify(sc)
		}
		if sc := tls.GetValidationContextSdsSecretConfig(); sc != nil {
			qualify(sc)
		}
	}
	return updated
}

func fillInTransportSocketXDS(cecNamespace string, cecName string, ts *envoy_config_core.TransportSocket) {
	if ts != nil {
		if tc := ts.GetTypedConfig(); tc != nil {
			any, err := tc.UnmarshalNew()
			if err != nil {
				return
			}
			var updated *anypb.Any
			switch tls := any.(type) {
			case *envoy_config_tls.DownstreamTlsContext:
				if fillInTlsContextXDS(cecNamespace, cecName, tls.CommonTlsContext) {
					updated = toAny(tls)
				}
			case *envoy_config_tls.UpstreamTlsContext:
				if fillInTlsContextXDS(cecNamespace, cecName, tls.CommonTlsContext) {
					updated = toAny(tls)
				}
			}
			if updated != nil {
				ts.ConfigType = &envoy_config_core.TransportSocket_TypedConfig{
					TypedConfig: updated,
				}
			}
		}
	}
}
