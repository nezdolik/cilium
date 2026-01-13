package xdsnew

import (
	"fmt"
	"maps"
	"strings"

	cilium "github.com/cilium/proxy/go/cilium/api"
	"github.com/cilium/proxy/pkg/policy/api/kafka"
	envoy_config_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_upstream_codec "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/upstream_codec/v3"
	envoy_config_http "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_type_matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"

	util "github.com/cilium/cilium/pkg/envoy/util"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/ipcache"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/proxy/endpoint"
)

const (
	CiliumXDSClusterName = "xds-grpc-cilium"
)

type Resource interface {
	proto.Message
}

func ToAny(pb proto.Message) *anypb.Any {
	a, err := anypb.New(pb)
	if err != nil {
		panic(err.Error())
	}
	return a
}

func GetCiliumHttpFilter() *envoy_config_http.HttpFilter {
	return &envoy_config_http.HttpFilter{
		Name: "cilium.l7policy",
		ConfigType: &envoy_config_http.HttpFilter_TypedConfig{
			TypedConfig: ToAny(&cilium.L7Policy{
				AccessLogPath:  util.GetAccessLogSocketPath(util.GetSocketDir(option.Config.RunDir)),
				Denied_403Body: option.Config.HTTP403Message,
			}),
		},
	}
}

func GetUpstreamCodecFilter() *envoy_config_http.HttpFilter {
	return &envoy_config_http.HttpFilter{
		Name: "envoy.filters.http.upstream_codec",
		ConfigType: &envoy_config_http.HttpFilter_TypedConfig{
			TypedConfig: ToAny(&envoy_upstream_codec.UpstreamCodec{}),
		},
	}
}

func getPublicListenerAddress(port uint16, ipv4, ipv6 bool) *envoy_config_core.Address {
	listenerAddr := "0.0.0.0"
	if ipv6 {
		listenerAddr = "::"
	}
	return &envoy_config_core.Address{
		Address: &envoy_config_core.Address_SocketAddress{
			SocketAddress: &envoy_config_core.SocketAddress{
				Protocol:      envoy_config_core.SocketAddress_TCP,
				Address:       listenerAddr,
				Ipv4Compat:    ipv4 && ipv6,
				PortSpecifier: &envoy_config_core.SocketAddress_PortValue{PortValue: uint32(port)},
			},
		},
	}
}

func GetLocalListenerAddresses(port uint16, ipv4, ipv6 bool) (*envoy_config_core.Address, []*envoy_config_listener.AdditionalAddress) {
	addresses := []*envoy_config_core.Address_SocketAddress{}

	if ipv4 {
		addresses = append(addresses, &envoy_config_core.Address_SocketAddress{
			SocketAddress: &envoy_config_core.SocketAddress{
				Protocol:      envoy_config_core.SocketAddress_TCP,
				Address:       "127.0.0.1",
				PortSpecifier: &envoy_config_core.SocketAddress_PortValue{PortValue: uint32(port)},
			},
		})
	}

	if ipv6 {
		addresses = append(addresses, &envoy_config_core.Address_SocketAddress{
			SocketAddress: &envoy_config_core.SocketAddress{
				Protocol:      envoy_config_core.SocketAddress_TCP,
				Address:       "::1",
				PortSpecifier: &envoy_config_core.SocketAddress_PortValue{PortValue: uint32(port)},
			},
		})
	}

	var additionalAddress []*envoy_config_listener.AdditionalAddress

	if len(addresses) > 1 {
		additionalAddress = append(additionalAddress, &envoy_config_listener.AdditionalAddress{
			Address: &envoy_config_core.Address{
				Address: addresses[1],
			},
		})
	}

	return &envoy_config_core.Address{
		Address: addresses[0],
	}, additionalAddress
}

func getListenerFilter(isIngress bool, useOriginalSourceAddr bool, proxyPort uint16, lingerConfig int) *envoy_config_listener.ListenerFilter {
	conf := &cilium.BpfMetadata{
		IsIngress:                isIngress,
		UseOriginalSourceAddress: useOriginalSourceAddr,
		BpfRoot:                  bpf.BPFFSRoot(),
		IsL7Lb:                   false,
		ProxyId:                  uint32(proxyPort),
		IpcacheName:              ipcache.Name,
	}

	if lingerConfig >= 0 {
		lingerTime := uint32(lingerConfig)
		conf.OriginalSourceSoLingerTime = &lingerTime
	}

	return &envoy_config_listener.ListenerFilter{
		Name: "cilium.bpf_metadata",
		ConfigType: &envoy_config_listener.ListenerFilter_TypedConfig{
			TypedConfig: ToAny(conf),
		},
	}
}

func GetInternalListenerCIDRs(ipv4, ipv6 bool) []*envoy_config_core.CidrRange {
	var cidrRanges []*envoy_config_core.CidrRange

	if ipv4 {
		cidrRanges = append(cidrRanges,
			[]*envoy_config_core.CidrRange{
				{AddressPrefix: "10.0.0.0", PrefixLen: &wrapperspb.UInt32Value{Value: 8}},
				{AddressPrefix: "172.16.0.0", PrefixLen: &wrapperspb.UInt32Value{Value: 12}},
				{AddressPrefix: "192.168.0.0", PrefixLen: &wrapperspb.UInt32Value{Value: 16}},
				{AddressPrefix: "127.0.0.1", PrefixLen: &wrapperspb.UInt32Value{Value: 32}},
			}...)
	}

	if ipv6 {
		cidrRanges = append(cidrRanges, &envoy_config_core.CidrRange{
			AddressPrefix: "::1",
			PrefixLen:     &wrapperspb.UInt32Value{Value: 128},
		})
	}
	return cidrRanges
}

func getL7Rules(l7Rules []api.PortRuleL7, l7Proto string) *cilium.L7NetworkPolicyRules {
	allowRules := make([]*cilium.L7NetworkPolicyRule, 0, len(l7Rules))
	denyRules := make([]*cilium.L7NetworkPolicyRule, 0, len(l7Rules))
	useEnvoyMetadataMatcher := strings.HasPrefix(l7Proto, "envoy.")

	for _, l7 := range l7Rules {
		if useEnvoyMetadataMatcher {
			envoyFilterName := l7Proto
			rule := &cilium.L7NetworkPolicyRule{MetadataRule: make([]*envoy_type_matcher.MetadataMatcher, 0, len(l7))}
			denyRule := false
			for k, v := range l7 {
				switch k {
				case "action":
					switch v {
					case "deny":
						denyRule = true
					}
				default:
					// map key to path segments and value to value matcher
					// For now only one path segment is allowed
					segments := strings.Split(k, "/")
					var path []*envoy_type_matcher.MetadataMatcher_PathSegment
					for _, key := range segments {
						path = append(path, &envoy_type_matcher.MetadataMatcher_PathSegment{
							Segment: &envoy_type_matcher.MetadataMatcher_PathSegment_Key{Key: key},
						})
					}
					var value *envoy_type_matcher.ValueMatcher
					if len(v) == 0 {
						value = &envoy_type_matcher.ValueMatcher{
							MatchPattern: &envoy_type_matcher.ValueMatcher_PresentMatch{
								PresentMatch: true,
							},
						}
					} else {
						value = &envoy_type_matcher.ValueMatcher{
							MatchPattern: &envoy_type_matcher.ValueMatcher_ListMatch{
								ListMatch: &envoy_type_matcher.ListMatcher{
									MatchPattern: &envoy_type_matcher.ListMatcher_OneOf{
										OneOf: &envoy_type_matcher.ValueMatcher{
											MatchPattern: &envoy_type_matcher.ValueMatcher_StringMatch{
												StringMatch: &envoy_type_matcher.StringMatcher{
													MatchPattern: &envoy_type_matcher.StringMatcher_Exact{
														Exact: v,
													},
													IgnoreCase: false,
												},
											},
										},
									},
								},
							},
						}
					}
					rule.MetadataRule = append(rule.MetadataRule, &envoy_type_matcher.MetadataMatcher{
						Filter: envoyFilterName,
						Path:   path,
						Value:  value,
					})
				}
			}
			if denyRule {
				denyRules = append(denyRules, rule)
			} else {
				allowRules = append(allowRules, rule)
			}
		} else {
			// proxylib go extension key/value policy
			rule := &cilium.L7NetworkPolicyRule{Rule: make(map[string]string, len(l7))}
			maps.Copy(rule.Rule, l7)
			allowRules = append(allowRules, rule)
		}
	}

	rules := &cilium.L7NetworkPolicyRules{}
	if len(allowRules) > 0 {
		rules.L7AllowRules = allowRules
	}
	if len(denyRules) > 0 {
		rules.L7DenyRules = denyRules
	}
	return rules
}

func getKafkaL7Rules(l7Rules []kafka.PortRule) *cilium.KafkaNetworkPolicyRules {
	allowRules := make([]*cilium.KafkaNetworkPolicyRule, 0, len(l7Rules))
	for _, kr := range l7Rules {
		rule := &cilium.KafkaNetworkPolicyRule{
			ApiVersion: kr.GetAPIVersion(),
			ApiKeys:    kr.GetAPIKeys(),
			ClientId:   kr.ClientID,
			Topic:      kr.Topic,
		}
		allowRules = append(allowRules, rule)
	}

	rules := &cilium.KafkaNetworkPolicyRules{}
	if len(allowRules) > 0 {
		rules.KafkaRules = allowRules
	}
	return rules
}

var CiliumXDSConfigSourceNew = &envoy_config_core.ConfigSource{
	InitialFetchTimeout: &durationpb.Duration{Seconds: 30},
	ResourceApiVersion:  envoy_config_core.ApiVersion_V3,
	ConfigSourceSpecifier: &envoy_config_core.ConfigSource_ApiConfigSource{
		ApiConfigSource: &envoy_config_core.ApiConfigSource{
			ApiType:                   envoy_config_core.ApiConfigSource_GRPC,
			TransportApiVersion:       envoy_config_core.ApiVersion_V3,
			SetNodeOnFirstMessageOnly: true,
			GrpcServices: []*envoy_config_core.GrpcService{
				{
					TargetSpecifier: &envoy_config_core.GrpcService_EnvoyGrpc_{
						EnvoyGrpc: &envoy_config_core.GrpcService_EnvoyGrpc{
							ClusterName: CiliumXDSClusterName,
						},
					},
				},
			},
		},
	},
}

// toEnvoyOriginatingTLSContext converts a "policy" TLS context (i.e., from a CiliumNetworkPolicy or
// CiliumClusterwideNetworkPolicy) for originating TLS (i.e., verifying TLS connections from *outside*) into a "cilium
// envoy" TLS context (i.e., for the Cilium proxy plugin for Envoy).
//
// useFullTLSContext is used to retain an old, buggy behavior where Secrets may contain a `ca.crt` field as well, which can
// lead Envoy to enforce client TLS between the client pod and the interception point in Envoy. In this case,
// Secrets will be sent to Envoy via the old, inline-in-NPDS method, and _not_ via SDS, and so this method will
// return whatever is in the *policy.TLSContext.
func toEnvoyOriginatingTLSContext(tls *policy.TLSContext, policySecretsNamespace string, useSDS, useFullTLSContext bool) *cilium.TLSContext {
	if !tls.FromFile && useSDS && policySecretsNamespace != "" {
		// If values are not present in these fields, then we should be using SDS,
		// and Secret should be populated.
		if tls.Secret.String() != "/" {
			return &cilium.TLSContext{
				ValidationContextSdsSecret: namespacedNametoSyncedSDSSecretName(tls.Secret, policySecretsNamespace),
			}
		}
		// This code _should_ be unreachable, because NetworkPolicy input validation does not allow
		// the Secret fields to be empty, so panic.
		panic("SDS Policy secrets cannot be empty, this should not be possible, please log an issue")
	}

	// If we are not using a synchronized secret or are reading from file, useFullTLSContext
	// matters.
	if useFullTLSContext {
		return &cilium.TLSContext{
			CertificateChain: tls.CertificateChain,
			PrivateKey:       tls.PrivateKey,
			TrustedCa:        tls.TrustedCA,
		}
	}

	return &cilium.TLSContext{
		TrustedCa: tls.TrustedCA,
	}
}

// toEnvoyTerminatingTLSContext converts a "policy" TLS context (i.e., from a CiliumNetworkPolicy or
// CiliumClusterwideNetworkPolicy) for terminating TLS (i.e., providing a valid cert to clients *inside*) into a "cilium
// envoy" TLS context (i.e., for the Cilium proxy plugin for Envoy).
//
// useFullTLSContext is used to retain an old, buggy behavior where Secrets may contain a `ca.crt` field as well, which can
// lead Envoy to enforce client TLS between the client pod and the interception point in Envoy. In this case,
// Secrets will be sent to Envoy via the old, inline-in-NPDS method, and _not_ via SDS, and so this method will
// return whatever is in the *policy.TLSContext.
func toEnvoyTerminatingTLSContext(tls *policy.TLSContext, policySecretsNamespace string, useSDS, useFullTLSContext bool) *cilium.TLSContext {
	if !tls.FromFile && useSDS && policySecretsNamespace != "" {
		// If the values have been read from Kubernetes, then we should be using SDS,
		// and Secret should be populated.
		if tls.Secret.String() != "/" {
			return &cilium.TLSContext{
				TlsSdsSecret: namespacedNametoSyncedSDSSecretName(tls.Secret, policySecretsNamespace),
			}
		}
		// This code _should_ be unreachable, because NetworkPolicy input validation does not allow
		// the Secret fields to be empty, so panic.
		panic("SDS Policy secrets cannot be empty, this should not be possible, please log an issue")
	}

	// If we are not using a synchronized secret or are reading from file, useFullTLSContext
	// matters.
	if useFullTLSContext {
		return &cilium.TLSContext{
			CertificateChain: tls.CertificateChain,
			PrivateKey:       tls.PrivateKey,
			TrustedCa:        tls.TrustedCA,
		}
	}

	return &cilium.TLSContext{
		CertificateChain: tls.CertificateChain,
		PrivateKey:       tls.PrivateKey,
	}
}

func namespacedNametoSyncedSDSSecretName(namespacedName types.NamespacedName, policySecretsNamespace string) string {
	if policySecretsNamespace == "" {
		return fmt.Sprintf("%s/%s", namespacedName.Namespace, namespacedName.Name)
	}
	return fmt.Sprintf("%s/%s-%s", policySecretsNamespace, namespacedName.Namespace, namespacedName.Name)
}

// return the Envoy proxy node IDs that need to ACK the policy.
func GetNodeIDs(ep endpoint.EndpointUpdater, policy *policy.L4Policy) []string {
	nodeIDs := make([]string, 0, 1)

	// Host proxy uses "127.0.0.1" as the nodeID
	nodeIDs = append(nodeIDs, "127.0.0.1")
	// Require additional ACK from proxylib if policy has proxylib redirects
	// Note that if a previous policy had a proxylib redirect and this one does not,
	// we only wait for the ACK from the main Envoy node ID.
	if policy.HasProxylibRedirect() {
		// Proxylib uses "127.0.0.2" as the nodeID
		nodeIDs = append(nodeIDs, "127.0.0.2")
	}
	return nodeIDs
}
