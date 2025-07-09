// TypeScript Learning: Types, Interfaces, and Advanced Concepts

// =============================================================================
// 1. BASIC TYPES (like Go's basic types)
// =============================================================================

// Primitive types (similar to Go)
const userName: string = 'John'; // like Go's string
const userAge: number = 30; // like Go's int (no separate int/float64)
const isActive: boolean = true; // like Go's bool
const data: any = { foo: 'bar' }; // like Go's interface{} - avoid this!

// =============================================================================
// 2. ARRAYS AND OBJECTS (different from Go)
// =============================================================================

// Arrays (like Go slices but typed)
const numbers: number[] = [1, 2, 3];
const names: Array<string> = ['Alice', 'Bob']; // Generic syntax
const mixed: (string | number)[] = ['Alice', 42]; // Union types!

// Objects (like Go maps but structured)
const user: { name: string; age: number } = {
  name: 'John',
  age: 30,
};

// =============================================================================
// 3. INTERFACES (like Go interfaces but for structure, not behavior)
// =============================================================================

// Basic interface - defines object shape
interface User {
  id: string;
  name: string;
  email: string;
  age?: number; // Optional property (like Go pointers but simpler)
}

// Interface with methods (like Go interfaces)
interface Logger {
  log(message: string): void;
  error(message: string, error: Error): void;
}

// Interface inheritance (extending)
interface AdminUser extends User {
  permissions: string[];
  lastLogin?: Date; // Optional Date
}

// =============================================================================
// 4. UNION TYPES (no direct Go equivalent - very powerful!)
// =============================================================================

// Union types - value can be one of several types
type Status = 'pending' | 'active' | 'inactive'; // Like Go enums but better
type ID = string | number; // Flexible ID type

// Function with union type parameter
function processStatus(status: Status): string {
  switch (status) {
    case 'pending':
      return 'Waiting for approval';
    case 'active':
      return 'User is active';
    case 'inactive':
      return 'User is disabled';
    // TypeScript ensures all cases are handled!
  }
}

// =============================================================================
// 5. GENERICS (like Go generics but more mature)
// =============================================================================

// Generic function (like Go's type parameters)
function getValue<T>(key: string, defaultValue: T): T {
  // In real code, this might fetch from a config
  return defaultValue;
}

// Usage
const stringValue = getValue<string>('name', 'default'); // Type is string
const numberValue = getValue<number>('age', 0); // Type is number

// Generic interface
interface ApiResponse<T> {
  success: boolean;
  data: T;
  error?: string;
}

// Usage with different data types
const userResponse: ApiResponse<User> = {
  success: true,
  data: { id: '1', name: 'John', email: 'john@example.com' },
};

const numbersResponse: ApiResponse<number[]> = {
  success: true,
  data: [1, 2, 3, 4, 5],
};

// =============================================================================
// 6. TYPE ALIASES (like Go type definitions)
// =============================================================================

// Simple type alias
type UserID = string;
type Timestamp = number;

// Complex type alias
type DatabaseConfig = {
  host: string;
  port: number;
  database: string;
  credentials: {
    username: string;
    password: string;
  };
};

// Function type alias (like Go function types)
type HandlerFunction = (req: any, res: any) => void;
type AsyncHandler = (req: any, res: any) => Promise<void>;

// =============================================================================
// 7. ENUMS (like Go iota but more explicit)
// =============================================================================

// String enum (preferred)
enum TransportType {
  STDIO = 'stdio',
  HTTP = 'streamable-http',
  SSE = 'sse',
}

// Numeric enum
enum LogLevel {
  DEBUG, // 0
  INFO, // 1
  WARN, // 2
  ERROR, // 3
}

// Usage
const transport: TransportType = TransportType.HTTP;
const level: LogLevel = LogLevel.ERROR;

// =============================================================================
// 8. LITERAL TYPES (very TypeScript-specific)
// =============================================================================

// Literal types - exact values
type Theme = 'dark' | 'light';
type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE';

// Template literal types (advanced!)
type EventName = `user-${string}`; // Must start with "user-"
type ApiEndpoint = `/api/v1/${string}`;

// =============================================================================
// 9. UTILITY TYPES (TypeScript's built-in helpers)
// =============================================================================

// Partial - makes all properties optional
type PartialUser = Partial<User>; // All properties become optional

// Pick - select specific properties
type UserSummary = Pick<User, 'id' | 'name'>; // Only id and name

// Omit - exclude specific properties
type CreateUser = Omit<User, 'id'>; // User without id

// Record - key-value mapping
type UserRoles = Record<string, string[]>; // userId -> roles

// =============================================================================
// 10. COMPARISON TO GO
// =============================================================================

/*
Go Struct:
type User struct {
    ID    string `json:"id"`
    Name  string `json:"name"`
    Email string `json:"email"`
    Age   *int   `json:"age,omitempty"`
}

TypeScript Interface:
interface User {
    id: string;
    name: string;
    email: string;
    age?: number;  // Optional, like Go pointer
}

Go Interface:
type Writer interface {
    Write([]byte) (int, error)
}

TypeScript Interface:
interface Writer {
    write(data: Uint8Array): Promise<number>;
}

Go Union (doesn't exist, use interface{}):
var value interface{} = "string or number"

TypeScript Union:
type Value = string | number;
const value: Value = "string or number";
*/

// =============================================================================
// 11. PRACTICAL EXAMPLES FOR OUR GATEWAY
// =============================================================================

// Service configuration (like your Go config)
interface ServiceConfig {
  id: string;
  slug: string;
  displayName: string;
  transportType: TransportType;
  mcpServerUrl?: string;
  authType: 'pat' | 'api_key' | 'oauth' | 'no_auth';
  authConfig: Record<string, any>; // Flexible auth config
}

// MCP Tool definition
interface MCPTool {
  name: string;
  description?: string;
  inputSchema: Record<string, any>;
}

// Gateway response types
type GatewayResponse<T = any> =
  | {
      success: true;
      data: T;
    }
  | {
      success: false;
      error: string;
      code?: number;
    };

// Export for use in other files
export {
  User,
  Logger,
  AdminUser,
  ServiceConfig,
  MCPTool,
  TransportType,
  LogLevel,
  GatewayResponse,
};
