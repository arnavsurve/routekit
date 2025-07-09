// TypeScript Learning: Error Handling Patterns
// Comparing Go's explicit error handling with TypeScript approaches

// =============================================================================
// 1. GO vs TYPESCRIPT ERROR HANDLING PHILOSOPHY
// =============================================================================

/*
Go Philosophy: Explicit error handling, errors are values
func DoSomething() (result string, err error) {
    if someCondition {
        return "", errors.New("something went wrong")
    }
    return "success", nil
}

result, err := DoSomething()
if err != nil {
    // Handle error
}
*/

/*
TypeScript Philosophy: Exceptions with try/catch, but also supports Go-style
async function doSomething(): Promise<string> {
    if (someCondition) {
        throw new Error("something went wrong");
    }
    return "success";
}

try {
    const result = await doSomething();
} catch (error) {
    // Handle error
}
*/

// =============================================================================
// 2. TYPESCRIPT ERROR TYPES
// =============================================================================

// Custom error classes (like Go's custom error types)
class ValidationError extends Error {
  constructor(
    message: string,
    public field: string,
    public value: any,
  ) {
    super(message);
    this.name = 'ValidationError';
  }
}

class DatabaseError extends Error {
  constructor(
    message: string,
    public query: string,
    public originalError: Error,
  ) {
    super(message);
    this.name = 'DatabaseError';
  }
}

class AuthenticationError extends Error {
  constructor(
    message: string,
    public statusCode: number = 401,
  ) {
    super(message);
    this.name = 'AuthenticationError';
  }
}

// =============================================================================
// 3. GO-STYLE ERROR HANDLING IN TYPESCRIPT (Result pattern)
// =============================================================================

// Result type - like Go's (value, error) return pattern
type Result<T, E = Error> = { success: true; data: T } | { success: false; error: E };

// Helper functions for Result pattern
function ok<T>(data: T): Result<T> {
  return { success: true, data };
}

function err<E = Error>(error: E): Result<never, E> {
  return { success: false, error };
}

// Function using Result pattern (Go-style)
async function validateUser(userData: any): Promise<Result<{ id: string; name: string }>> {
  // Validation logic
  if (!userData.name) {
    return err(new ValidationError('Name is required', 'name', userData.name));
  }

  if (!userData.email || !userData.email.includes('@')) {
    return err(new ValidationError('Valid email is required', 'email', userData.email));
  }

  // Success case
  return ok({ id: 'user-123', name: userData.name });
}

// Using Result pattern (like Go error checking)
async function handleUserValidation(userData: any): Promise<void> {
  const result = await validateUser(userData);

  if (!result.success) {
    // Handle error (like Go's if err != nil)
    console.error('Validation failed:', result.error.message);
    if (result.error instanceof ValidationError) {
      console.error('Field:', result.error.field, 'Value:', result.error.value);
    }
    return;
  }

  // Use successful result
  console.log('User validated:', result.data);
}

// =============================================================================
// 4. TRADITIONAL TYPESCRIPT ERROR HANDLING
// =============================================================================

// Function that throws errors (traditional TypeScript way)
async function connectToDatabase(config: DatabaseConfig): Promise<DatabaseConnection> {
  try {
    // Simulate connection
    if (!config.host) {
      throw new ValidationError('Database host is required', 'host', config.host);
    }

    if (config.port < 1 || config.port > 65535) {
      throw new ValidationError('Invalid port number', 'port', config.port);
    }

    // Simulate database connection failure
    if (config.host === 'bad-host') {
      throw new DatabaseError(
        'Connection failed',
        'CONNECT TO DATABASE',
        new Error('Host unreachable'),
      );
    }

    // Success - return connection
    return {
      host: config.host,
      port: config.port,
      connected: true,
      query: async () => [],
      close: async () => {},
    };
  } catch (error) {
    // Re-throw with more context
    if (error instanceof ValidationError || error instanceof DatabaseError) {
      throw error;
    }
    throw new DatabaseError('Unknown database error', 'CONNECT', error as Error);
  }
}

// =============================================================================
// 5. ERROR HANDLING IN EXPRESS MIDDLEWARE
// =============================================================================

// Error handling middleware (like Go's middleware pattern)
import { Request, Response, NextFunction } from 'express';

// Error response type
interface ErrorResponse {
  error: string;
  code: string;
  details?: any;
  timestamp: string;
}

// Global error handler middleware
function errorHandler(error: Error, req: Request, res: Response, next: NextFunction): void {
  console.error('Error occurred:', error);

  let statusCode = 500;
  let errorResponse: ErrorResponse = {
    error: 'Internal Server Error',
    code: 'INTERNAL_ERROR',
    timestamp: new Date().toISOString(),
  };

  // Handle specific error types
  if (error instanceof ValidationError) {
    statusCode = 400;
    errorResponse = {
      error: error.message,
      code: 'VALIDATION_ERROR',
      details: { field: error.field, value: error.value },
      timestamp: new Date().toISOString(),
    };
  } else if (error instanceof AuthenticationError) {
    statusCode = error.statusCode;
    errorResponse = {
      error: error.message,
      code: 'AUTH_ERROR',
      timestamp: new Date().toISOString(),
    };
  } else if (error instanceof DatabaseError) {
    statusCode = 500;
    errorResponse = {
      error: 'Database operation failed',
      code: 'DATABASE_ERROR',
      details: { query: error.query },
      timestamp: new Date().toISOString(),
    };
  }

  res.status(statusCode).json(errorResponse);
}

// Async error wrapper (catches async errors automatically)
function asyncHandler<T extends Request, U extends Response>(
  fn: (req: T, res: U, next: NextFunction) => Promise<any>,
) {
  return (req: T, res: U, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

// =============================================================================
// 6. PRACTICAL ERROR HANDLING FOR OUR GATEWAY
// =============================================================================

// Service connection with comprehensive error handling
async function createServiceConnection(config: ServiceConfig): Promise<Result<MCPClient>> {
  try {
    // Validate configuration
    if (!config.transportType) {
      return err(
        new ValidationError('Transport type is required', 'transportType', config.transportType),
      );
    }

    // Attempt connection based on transport type
    switch (config.transportType) {
      case 'stdio':
        return await createStdioConnection(config);
      case 'streamable-http':
        return await createHttpConnection(config);
      default:
        return err(
          new ValidationError('Unsupported transport type', 'transportType', config.transportType),
        );
    }
  } catch (error) {
    return err(new Error(`Failed to create service connection: ${error}`));
  }
}

// Specific connection methods with error handling
async function createHttpConnection(config: ServiceConfig): Promise<Result<MCPClient>> {
  if (!config.mcpServerUrl) {
    return err(
      new ValidationError(
        'MCP server URL is required for HTTP transport',
        'mcpServerUrl',
        config.mcpServerUrl,
      ),
    );
  }

  try {
    // Create HTTP client (this would be actual MCP SDK code)
    const client: MCPClient = {
      id: config.id,
      connected: true,
      transport: 'http',
    };

    return ok(client);
  } catch (error) {
    return err(new Error(`HTTP connection failed: ${error}`));
  }
}

async function createStdioConnection(config: ServiceConfig): Promise<Result<MCPClient>> {
  try {
    // Create stdio client
    const client: MCPClient = {
      id: config.id,
      connected: true,
      transport: 'stdio',
    };

    return ok(client);
  } catch (error) {
    return err(new Error(`Stdio connection failed: ${error}`));
  }
}

// =============================================================================
// 7. ERROR HANDLING COMPARISON SUMMARY
// =============================================================================

/*
GO PATTERN:
client, err := createClient(config)
if err != nil {
    log.Printf("Error: %v", err)
    return nil, err
}

TYPESCRIPT RESULT PATTERN (Go-style):
const result = await createServiceConnection(config);
if (!result.success) {
    console.error("Error:", result.error.message);
    return;
}
const client = result.data;

TYPESCRIPT TRY/CATCH PATTERN:
try {
    const client = await createServiceConnection(config);
    // Use client
} catch (error) {
    console.error("Error:", error.message);
    return;
}

WHICH TO USE?
- Result pattern: When you want Go-style explicit error handling
- Try/catch: When you want traditional JavaScript/Java-style exception handling
- Both are valid! Choose based on team preference and consistency
*/

// Type definitions
interface DatabaseConfig {
  host: string;
  port: number;
  database: string;
}

interface DatabaseConnection {
  host: string;
  port: number;
  connected: boolean;
  query: () => Promise<any[]>;
  close: () => Promise<void>;
}

interface ServiceConfig {
  id: string;
  transportType: 'stdio' | 'streamable-http' | 'sse';
  mcpServerUrl?: string;
}

interface MCPClient {
  id: string;
  connected: boolean;
  transport: string;
}

// Export everything
export {
  ValidationError,
  DatabaseError,
  AuthenticationError,
  Result,
  ok,
  err,
  validateUser,
  connectToDatabase,
  errorHandler,
  asyncHandler,
  createServiceConnection,
  DatabaseConfig,
  DatabaseConnection,
  ServiceConfig,
  MCPClient,
};
