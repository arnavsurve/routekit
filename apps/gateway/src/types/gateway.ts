// --- Service configuration types (from DB) ---

export interface ServiceConfig {
  id: string;
  userId: string;
  slug: string;
  displayName: string;
  transportType: TransportType;
  mcpServerUrl?: string | undefined;
  authType: AuthType;
  scopes: string[];
  audience?: string | undefined;
}

export type TransportType = 'stdio' | 'streamable-http' | 'sse';

export type AuthType =
  | 'pat'
  | 'api_key_in_header'
  | 'api_key_in_url'
  | 'oauth'
  | 'no_auth'
  | 'mcp_remote_managed';

export interface AuthConfig {
  token?: string; // PAT
  apiKey?: string; // API key auth
  headerName?: string; // Header-based auth
  queryParamName?: string;
  clientId?: string;
  clientSecret?: string;
  [key: string]: any; // Additional auth config fields
}

// --- Database types ---

export interface DatabaseConfig {
  host: string;
  port: number;
  database: string;
  username: string;
  password: string;
}

export interface ServiceConfigRow {
  id: string;
  user_id: string;
  service_slug: string;
  display_name: string;
  transport_type: string;
  mcp_server_url: string | null;
  auth_type: string;
  auth_config_encrypted: string;
  scopes: string | null; // JSON string
  audience: string | null;
}

// --- JWT authentication types ---

export interface JWTPayload {
  user_id: string;
  iat?: number;
  exp?: number;
}

export interface AuthenticatedRequest {
  userId: string;
}

// --- MCP types (extending SDK types) ---

export interface MCPTool {
  name: string;
  description?: string;
  inputSchema: Record<string, any>;
}

export interface MCPResource {
  uri: string;
  name?: string;
  description?: string;
  mimeType?: string;
}

export interface MCPClient {
  id: string;
  serviceSlug: string;
  transport: string;
  connected: boolean;
  lastUsed: Date;
}

// --- Gateway response types ---

export type GatewayResult<T> =
  | { success: true; data: T }
  | { success: false; error: string; code?: string };

export interface ToolExecutionResponse {
  content: Array<{
    type: 'text' | 'image' | 'resource';
    text?: string;
    data?: string;
    uri?: string;
  }>;
  isError?: boolean;
}

export interface ServiceInfo {
  service_slug: string;
  display_name: string;
}

export interface ServicesResponse {
  services: ServiceInfo[];
}

export interface ToolsResponse {
  tools: MCPTool[];
}

export interface ResourcesResponse {
  resources: MCPResource[];
}

// --- Error types ---

export class GatewayError extends Error {
  constructor(
    message: string,
    public code: string,
    public statusCode: number = 500,
    public details?: any,
  ) {
    super(message);
    this.name = 'GatewayError';
  }
}

export class AuthenticationError extends GatewayError {
  constructor(message: string = 'Authentication failed') {
    super(message, 'AUTH_ERROR', 401);
  }
}

export class ValidationError extends GatewayError {
  constructor(message: string, field?: string, value?: any) {
    super(message, 'VALIDATION_ERROR', 400, { field, value });
  }
}

export class ServiceConnectionError extends GatewayError {
  constructor(serviceName: string, originalError: Error) {
    super(`Failed to connect to service: ${serviceName}`, 'SERVICE_CONNECTION_ERROR', 503, {
      serviceName,
      originalError: originalError.message,
    });
  }
}

export class ToolConnectionError extends GatewayError {
  constructor(toolName: string, originalError: Error) {
    super(`Tool execution failed: ${toolName}`, 'TOOL_EXECUTION_ERROR', 500, {
      toolName,
      originalError: originalError.message,
    });
  }
}

// --- Request/response types for meta tools ---

export interface GetConnectedServicesRequest {}

export interface GetServiceToolsRequest {
  services: string[];
}

export interface ExecuteToolRequest {
  tool_name: string;
  tool_args: Record<string, any>;
}

export interface ListResourcesRequest {
  services: string[];
}

export interface ReadResourceRequest {
  resource_uri: string;
}

// --- Server configuration ---

export interface ServerConfig {
  port: number;
  host: string;
  jwtSecret: string;
  database: DatabaseConfig;
  encryptionKey: string;
}

export interface EnvironmentConfig {
  NODE_ENV: 'development' | 'production' | 'test';
  PORT: string;
  HOST: string;
  JWT_SECRET: string;
  DATABASE_URL: string;
  ENCRYPTION_KEY: string;
}

// --- Utility types ---

export type Awaited<T> = T extends PromiseLike<infer U> ? U : T;

export type Optional<T, K extends keyof T> = Omit<T, K> & Partial<Pick<T, K>>;

export type RequireField<T, K extends keyof T> = T & Required<Pick<T, K>>;

// Helper type for DB operations
export type CreateServiceConfig = Omit<ServiceConfig, 'id'>;
export type UpdateServiceConfig = Partial<Omit<ServiceConfig, 'id' | 'userId'>>;

// --- Type guards (runtime type checking) ---

export function isTransportType(value: string): value is TransportType {
  return ['stdio', 'streamable-http', 'sse'].includes(value);
}

export function isAuthType(value: string): value is AuthType {
  return [
    'pat',
    'api_key_in_header',
    'api_key_in_url',
    'oauth',
    'no_auth',
    'mcp_remote_managed',
  ].includes(value);
}

export function isValidServiceConfig(config: any): config is ServiceConfig {
  return (
    typeof config === 'object' &&
    typeof config.id === 'string' &&
    typeof config.slug === 'string' &&
    typeof config.displayName === 'string' &&
    isTransportType(config.transportType) &&
    isAuthType(config.authType) &&
    typeof config.AuthConfig === 'object' &&
    Array.isArray(config.scopes)
  );
}
