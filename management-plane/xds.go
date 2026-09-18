package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extcorev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	wasmcorev3 "github.com/envoyproxy/go-control-plane/envoy/extensions/wasm/v3"
	wasmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/wasm/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	extensionconfigv3 "github.com/envoyproxy/go-control-plane/envoy/service/extension/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/envoyproxy/go-control-plane/pkg/server/v3"
	"github.com/envoyproxy/go-control-plane/pkg/test/v3"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	snapshotCache cache.SnapshotCache
	version       int
	mu            sync.Mutex
)

const (
	NodeID        = "waf_node_1"
	ExtensionName = "coraza-wasm-config"
	// DefaultRuleSet is stored as plain SecLang directives (one per line).
	// The JSON wrapper required by coraza-proxy-wasm is assembled server-side.
	DefaultRuleSet = `SecRuleEngine On
SecRequestBodyAccess On
SecAuditEngine RelevantOnly
SecAuditLogParts ABHKZ
SecAuditLogFormat JSON
SecAuditLog /dev/stdout
SecRule REQUEST_URI "@rx ^/" "id:1000,phase:1,pass,nolog,auditlog"
SecRule REQUEST_HEADERS:Content-Type "@rx (?i)application/json" "id:200001,phase:1,t:none,pass,nolog,ctl:requestBodyProcessor=JSON"
Include @crs-setup-conf
Include @owasp_crs/*.conf
SecRule REQUEST_URI "@streq /admin" "id:101,phase:1,t:lowercase,deny,msg:'Admin access denied'"`
)

// buildCorazaJSON converts plain SecLang directives (one per line) to the
// JSON configuration format expected by coraza-proxy-wasm.
func buildCorazaJSON(secLangDirectives string) string {
	// Split lines, filter empties, JSON-encode each directive string.
	lines := strings.Split(secLangDirectives, "\n")
	var encoded []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		b, err := json.Marshal(line)
		if err != nil {
			continue
		}
		encoded = append(encoded, string(b))
	}
	directives := strings.Join(encoded, ",\n\t\t\t")
	return fmt.Sprintf(`{
	"directives_map": {
		"default": [
			%s
		]
	},
	"default_directives": "default"
}`, directives)
}

// RunXDSServer starts the gRPC xDS server on the specified port.
func RunXDSServer(port int) {
	snapshotCache = cache.NewSnapshotCache(false, cache.IDHash{}, nil)

	// Create initial snapshot
	UpdateWAFConfig(DefaultRuleSet)

	cb := &test.Callbacks{Debug: true}
	srv := server.NewServer(context.Background(), snapshotCache, cb)

	grpcServer := grpc.NewServer()
	discoveryv3.RegisterAggregatedDiscoveryServiceServer(grpcServer, srv)
	extensionconfigv3.RegisterExtensionConfigDiscoveryServiceServer(grpcServer, srv)

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatalf("failed to listen on port %d: %v", port, err)
	}

	log.Printf("xDS server listening on port %d", port)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("failed to serve gRPC: %v", err)
	}
}

// UpdateWAFConfig accepts plain SecLang directives, builds the Coraza JSON config,
// and pushes a new xDS snapshot to Envoy.
func UpdateWAFConfig(secLangDirectives string) {
	mu.Lock()
	defer mu.Unlock()

	version++
	verStr := fmt.Sprintf("v%d", version)

	// Build Coraza JSON config from plain SecLang directives
	corazaJSON := buildCorazaJSON(secLangDirectives)
	configVal := wrapperspb.String(corazaJSON)
	configAny, _ := anypb.New(configVal)

	wasmConfig := &wasmv3.Wasm{
		Config: &wasmcorev3.PluginConfig{
			Name:   "coraza-filter",
			RootId: "",
			Vm: &wasmcorev3.PluginConfig_VmConfig{
				VmConfig: &wasmcorev3.VmConfig{
					Runtime: "envoy.wasm.runtime.v8",
					VmId:    "coraza-waf",
					Code: &extcorev3.AsyncDataSource{
						Specifier: &extcorev3.AsyncDataSource_Local{
							Local: &extcorev3.DataSource{
								Specifier: &extcorev3.DataSource_Filename{
									Filename: "/shared/coraza-proxy-wasm.wasm",
								},
							},
						},
					},
				},
			},
			Configuration: configAny,
		},
	}

	wasmAny, _ := anypb.New(wasmConfig)

	extensionConfig := &corev3.TypedExtensionConfig{
		Name:        ExtensionName,
		TypedConfig: wasmAny,
	}

	snap, _ := cache.NewSnapshot(verStr,
		map[resource.Type][]types.Resource{
			resource.ExtensionConfigType: {extensionConfig},
		},
	)

	// Push snapshot to the node
	if err := snapshotCache.SetSnapshot(context.Background(), NodeID, snap); err != nil {
		log.Printf("Failed to set snapshot %s: %v", verStr, err)
	} else {
		log.Printf("Pushed xDS snapshot %s to Envoy (Node: %s)", verStr, NodeID)
	}
}

func GetCurrentXDSVersion() string {
	mu.Lock()
	defer mu.Unlock()
	return fmt.Sprintf("v%d", version)
}

