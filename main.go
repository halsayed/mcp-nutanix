package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/thunderboltsid/mcp-nutanix/internal/client"
	"github.com/thunderboltsid/mcp-nutanix/pkg/prompts"
	"github.com/thunderboltsid/mcp-nutanix/pkg/resources"
	"github.com/thunderboltsid/mcp-nutanix/pkg/tools"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// ToolRegistration holds a tool function and its handler
type ToolRegistration struct {
	Func    func() mcp.Tool
	Handler server.ToolHandlerFunc
}

// ResourceRegistration represents a resource and its associated tools
type ResourceRegistration struct {
	Tools           []ToolRegistration
	ResourceFunc    func() mcp.ResourceTemplate
	ResourceHandler server.ResourceTemplateHandlerFunc
}

type serverConfig struct {
	transport       string
	httpAddr        string
	baseURL         string
	basePath        string
	messageEndpoint string
	sseEndpoint     string
}

// initializeFromEnvIfAvailable initializes the Prism client only if environment variables are available
func initializeFromEnvIfAvailable() {
	endpoint := os.Getenv("NUTANIX_ENDPOINT")
	username := os.Getenv("NUTANIX_USERNAME")
	password := os.Getenv("NUTANIX_PASSWORD")

	// Only initialize if all required environment variables are set
	// This allows prompt-based initialization to work when env vars are not present
	if endpoint != "" && username != "" && password != "" {
		client.Init(client.PrismClientProvider)
		fmt.Printf("Initialized Prism client from environment variables for endpoint: %s\n", endpoint)
	}
}

func envOrDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func normalizeEndpoint(value, fallback string) string {
	if value == "" {
		value = fallback
	}
	value = strings.TrimSpace(value)
	if value == "" {
		value = fallback
	}
	if !strings.HasPrefix(value, "/") {
		value = "/" + value
	}
	return value
}

func normalizeBasePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" || path == "/" {
		return ""
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return strings.TrimSuffix(path, "/")
}

func defaultBaseURL(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "http://localhost:8080"
	}

	host := "localhost"
	port := ""

	switch {
	case strings.HasPrefix(addr, ":"):
		host = "localhost"
		port = addr
	case strings.Contains(addr, ":"):
		if parsedHost, parsedPort, err := net.SplitHostPort(addr); err == nil {
			if parsedHost != "" {
				host = parsedHost
			}
			if parsedPort != "" {
				port = ":" + parsedPort
			}
		} else {
			host = addr
		}
	default:
		host = addr
	}

	if port == "" {
		port = ":80"
	}

	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}

	return fmt.Sprintf("http://%s%s", host, port)
}

func loadServerConfig() serverConfig {
	cfg := serverConfig{}

	flag.StringVar(
		&cfg.transport,
		"transport",
		envOrDefault("MCP_TRANSPORT", "stdio"),
		"Transport to use (stdio or sse)",
	)
	flag.StringVar(
		&cfg.httpAddr,
		"http-addr",
		envOrDefault("MCP_HTTP_ADDR", ":8080"),
		"HTTP listen address for SSE transport",
	)
	flag.StringVar(
		&cfg.baseURL,
		"base-url",
		os.Getenv("MCP_BASE_URL"),
		"Base URL clients should use to reach this server (e.g. http://localhost:8080)",
	)
	flag.StringVar(
		&cfg.basePath,
		"base-path",
		os.Getenv("MCP_BASE_PATH"),
		"Base path prefix for SSE endpoints (e.g. /mcp)",
	)
	flag.StringVar(
		&cfg.messageEndpoint,
		"message-endpoint",
		envOrDefault("MCP_MESSAGE_ENDPOINT", "/message"),
		"HTTP path for the MCP message endpoint",
	)
	flag.StringVar(
		&cfg.sseEndpoint,
		"sse-endpoint",
		envOrDefault("MCP_SSE_ENDPOINT", "/sse"),
		"HTTP path for the SSE stream endpoint",
	)

	flag.Parse()

	cfg.transport = strings.ToLower(strings.TrimSpace(cfg.transport))
	cfg.httpAddr = strings.TrimSpace(cfg.httpAddr)
	cfg.basePath = normalizeBasePath(cfg.basePath)
	cfg.messageEndpoint = normalizeEndpoint(cfg.messageEndpoint, "/message")
	cfg.sseEndpoint = normalizeEndpoint(cfg.sseEndpoint, "/sse")

	if cfg.baseURL == "" {
		cfg.baseURL = defaultBaseURL(cfg.httpAddr)
	} else {
		cfg.baseURL = strings.TrimRight(cfg.baseURL, "/")
	}

	return cfg
}

func startSSEServer(mcpServer *server.MCPServer, cfg serverConfig) error {
	opts := []server.SSEOption{
		server.WithBaseURL(cfg.baseURL),
		server.WithBasePath(cfg.basePath),
		server.WithMessageEndpoint(cfg.messageEndpoint),
		server.WithSSEEndpoint(cfg.sseEndpoint),
	}

	sseServer := server.NewSSEServer(mcpServer, opts...)

	fmt.Printf(
		"Starting SSE server on %s (SSE endpoint: %s, message endpoint: %s)\n",
		cfg.httpAddr,
		sseServer.CompleteSseEndpoint(),
		sseServer.CompleteMessageEndpoint(),
	)

	return sseServer.Start(cfg.httpAddr)
}

func main() {
	cfg := loadServerConfig()
	// Initialize the Prism client only if environment variables are available
	initializeFromEnvIfAvailable()

	// Define server hooks for logging and debugging
	hooks := &server.Hooks{}
	hooks.AddOnError(func(id any, method mcp.MCPMethod, message any, err error) {
		fmt.Printf("onError: %s, %v, %v, %v\n", method, id, message, err)
	})

	// Log level based on environment variable
	debugMode := os.Getenv("DEBUG") != ""
	if debugMode {
		hooks.AddBeforeAny(func(id any, method mcp.MCPMethod, message any) {
			fmt.Printf("beforeAny: %s, %v, %v\n", method, id, message)
		})
		hooks.AddOnSuccess(func(id any, method mcp.MCPMethod, message any, result any) {
			fmt.Printf("onSuccess: %s, %v, %v, %v\n", method, id, message, result)
		})
		hooks.AddBeforeInitialize(func(id any, message *mcp.InitializeRequest) {
			fmt.Printf("beforeInitialize: %v, %v\n", id, message)
		})
		hooks.AddAfterInitialize(func(id any, message *mcp.InitializeRequest, result *mcp.InitializeResult) {
			fmt.Printf("afterInitialize: %v, %v, %v\n", id, message, result)
		})
		hooks.AddAfterCallTool(func(id any, message *mcp.CallToolRequest, result *mcp.CallToolResult) {
			fmt.Printf("afterCallTool: %v, %v, %v\n", id, message, result)
		})
		hooks.AddBeforeCallTool(func(id any, message *mcp.CallToolRequest) {
			fmt.Printf("beforeCallTool: %v, %v\n", id, message)
		})
	}

	// Create a new MCP server
	s := server.NewMCPServer(
		"Prism Central",
		"0.0.1",
		server.WithResourceCapabilities(true, true),
		server.WithPromptCapabilities(true),
		server.WithLogging(),
		server.WithHooks(hooks),
	)

	// Add the prompts
	s.AddPrompt(prompts.SetCredentials(), prompts.SetCredentialsResponse())

	// Add standalone tools
	s.AddTool(tools.ApiNamespacesList(), tools.ApiNamespacesListHandler())

	// Define all resources and tools
	resourceRegistrations := map[string]ResourceRegistration{
		"vm": {
			Tools: []ToolRegistration{
				{
					Func:    tools.VMList,
					Handler: tools.VMListHandler(),
				},
				{
					Func:    tools.VMCount,
					Handler: tools.VMCountHandler(),
				},
			},
			ResourceFunc:    resources.VM,
			ResourceHandler: resources.VMHandler(),
		},
		"cluster": {
			Tools: []ToolRegistration{
				{
					Func:    tools.ClusterList,
					Handler: tools.ClusterListHandler(),
				},
				{
					Func:    tools.ClusterCount,
					Handler: tools.ClusterCountHandler(),
				},
			},
			ResourceFunc:    resources.Cluster,
			ResourceHandler: resources.ClusterHandler(),
		},
		"host": {
			Tools: []ToolRegistration{
				{
					Func:    tools.HostList,
					Handler: tools.HostListHandler(),
				},
				{
					Func:    tools.HostCount,
					Handler: tools.HostCountHandler(),
				},
			},
			ResourceFunc:    resources.Host,
			ResourceHandler: resources.HostHandler(),
		},
		"image": {
			Tools: []ToolRegistration{
				{
					Func:    tools.ImageList,
					Handler: tools.ImageListHandler(),
				},
				{
					Func:    tools.ImageCount,
					Handler: tools.ImageCountHandler(),
				},
			},
			ResourceFunc:    resources.Image,
			ResourceHandler: resources.ImageHandler(),
		},
		"subnet": {
			Tools: []ToolRegistration{
				{
					Func:    tools.SubnetList,
					Handler: tools.SubnetListHandler(),
				},
				{
					Func:    tools.SubnetCount,
					Handler: tools.SubnetCountHandler(),
				},
			},
			ResourceFunc:    resources.Subnet,
			ResourceHandler: resources.SubnetHandler(),
		},
		"project": {
			Tools: []ToolRegistration{
				{
					Func:    tools.ProjectList,
					Handler: tools.ProjectListHandler(),
				},
				{
					Func:    tools.ProjectCount,
					Handler: tools.ProjectCountHandler(),
				},
			},
			ResourceFunc:    resources.Project,
			ResourceHandler: resources.ProjectHandler(),
		},
		"volumegroup": {
			Tools: []ToolRegistration{
				{
					Func:    tools.VolumeGroupList,
					Handler: tools.VolumeGroupListHandler(),
				},
				{
					Func:    tools.VolumeGroupCount,
					Handler: tools.VolumeGroupCountHandler(),
				},
			},
			ResourceFunc:    resources.VolumeGroup,
			ResourceHandler: resources.VolumeGroupHandler(),
		},
		"networksecurityrule": {
			Tools: []ToolRegistration{
				{
					Func:    tools.NetworkSecurityRuleList,
					Handler: tools.NetworkSecurityRuleListHandler(),
				},
				{
					Func:    tools.NetworkSecurityRuleCount,
					Handler: tools.NetworkSecurityRuleCountHandler(),
				},
			},
			ResourceFunc:    resources.NetworkSecurityRule,
			ResourceHandler: resources.NetworkSecurityRuleHandler(),
		},
		"category": {
			Tools: []ToolRegistration{
				{
					Func:    tools.CategoryList,
					Handler: tools.CategoryListHandler(),
				},
				{
					Func:    tools.CategoryCount,
					Handler: tools.CategoryCountHandler(),
				},
			},
			ResourceFunc:    resources.Category,
			ResourceHandler: resources.CategoryHandler(),
		},
		"accesscontrolpolicy": {
			Tools: []ToolRegistration{
				{
					Func:    tools.AccessControlPolicyList,
					Handler: tools.AccessControlPolicyListHandler(),
				},
				{
					Func:    tools.AccessControlPolicyCount,
					Handler: tools.AccessControlPolicyCountHandler(),
				},
			},
			ResourceFunc:    resources.AccessControlPolicy,
			ResourceHandler: resources.AccessControlPolicyHandler(),
		},
		"role": {
			Tools: []ToolRegistration{
				{
					Func:    tools.RoleList,
					Handler: tools.RoleListHandler(),
				},
				{
					Func:    tools.RoleCount,
					Handler: tools.RoleCountHandler(),
				},
			},
			ResourceFunc:    resources.Role,
			ResourceHandler: resources.RoleHandler(),
		},
		"user": {
			Tools: []ToolRegistration{
				{
					Func:    tools.UserList,
					Handler: tools.UserListHandler(),
				},
				{
					Func:    tools.UserCount,
					Handler: tools.UserCountHandler(),
				},
			},
			ResourceFunc:    resources.User,
			ResourceHandler: resources.UserHandler(),
		},
		"usergroup": {
			Tools: []ToolRegistration{
				{
					Func:    tools.UserGroupList,
					Handler: tools.UserGroupListHandler(),
				},
				{
					Func:    tools.UserGroupCount,
					Handler: tools.UserGroupCountHandler(),
				},
			},
			ResourceFunc:    resources.UserGroup,
			ResourceHandler: resources.UserGroupHandler(),
		},
		"permission": {
			Tools: []ToolRegistration{
				{
					Func:    tools.PermissionList,
					Handler: tools.PermissionListHandler(),
				},
				{
					Func:    tools.PermissionCount,
					Handler: tools.PermissionCountHandler(),
				},
			},
			ResourceFunc:    resources.Permission,
			ResourceHandler: resources.PermissionHandler(),
		},
		"protectionrule": {
			Tools: []ToolRegistration{
				{
					Func:    tools.ProtectionRuleList,
					Handler: tools.ProtectionRuleListHandler(),
				},
				{
					Func:    tools.ProtectionRuleCount,
					Handler: tools.ProtectionRuleCountHandler(),
				},
			},
			ResourceFunc:    resources.ProtectionRule,
			ResourceHandler: resources.ProtectionRuleHandler(),
		},
		"recoveryplan": {
			Tools: []ToolRegistration{
				{
					Func:    tools.RecoveryPlanList,
					Handler: tools.RecoveryPlanListHandler(),
				},
				{
					Func:    tools.RecoveryPlanCount,
					Handler: tools.RecoveryPlanCountHandler(),
				},
			},
			ResourceFunc:    resources.RecoveryPlan,
			ResourceHandler: resources.RecoveryPlanHandler(),
		},
		"servicegroup": {
			Tools: []ToolRegistration{
				{
					Func:    tools.ServiceGroupList,
					Handler: tools.ServiceGroupListHandler(),
				},
				{
					Func:    tools.ServiceGroupCount,
					Handler: tools.ServiceGroupCountHandler(),
				},
			},
			ResourceFunc:    resources.ServiceGroup,
			ResourceHandler: resources.ServiceGroupHandler(),
		},
		"addressgroup": {
			Tools: []ToolRegistration{
				{
					Func:    tools.AddressGroupList,
					Handler: tools.AddressGroupListHandler(),
				},
				{
					Func:    tools.AddressGroupCount,
					Handler: tools.AddressGroupCountHandler(),
				},
			},
			ResourceFunc:    resources.AddressGroup,
			ResourceHandler: resources.AddressGroupHandler(),
		},
		"recoveryplanjob": {
			Tools: []ToolRegistration{
				{
					Func:    tools.RecoveryPlanJobList,
					Handler: tools.RecoveryPlanJobListHandler(),
				},
				{
					Func:    tools.RecoveryPlanJobCount,
					Handler: tools.RecoveryPlanJobCountHandler(),
				},
			},
			ResourceFunc:    resources.RecoveryPlanJob,
			ResourceHandler: resources.RecoveryPlanJobHandler(),
		},
	}

	// Register all tools and resources
	for name, registration := range resourceRegistrations {
		// Add all tools
		for _, tool := range registration.Tools {
			s.AddTool(tool.Func(), tool.Handler)
			if debugMode {
				fmt.Printf("Registered %s resource and tool\n", name)
			}
		}

		// Add the resource
		s.AddResourceTemplate(registration.ResourceFunc(), registration.ResourceHandler)
	}

	// Start the server
	switch cfg.transport {
	case "sse":
		if err := startSSEServer(s, cfg); err != nil {
			fmt.Printf("Server error: %v\n", err)
		}
	default:
		if err := server.ServeStdio(s); err != nil {
			fmt.Printf("Server error: %v\n", err)
		}
	}
}
