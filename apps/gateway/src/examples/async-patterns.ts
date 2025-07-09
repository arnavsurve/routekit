// TypeScript Learning: Async/Await vs Go Goroutines
// This file shows how TypeScript handles concurrency differently from Go

// =============================================================================
// 1. PROMISES - TypeScript's async primitive (like Go's channels)
// =============================================================================

// Basic Promise (like a Go channel with one value)
function fetchUserData(id: string): Promise<{ name: string; email: string }> {
  return new Promise((resolve, reject) => {
    // Simulate async operation (like a database call)
    setTimeout(() => {
      if (id === 'invalid') {
        reject(new Error('User not found'));
      } else {
        resolve({ name: 'John', email: 'john@example.com' });
      }
    }, 1000);
  });
}

// =============================================================================
// 2. ASYNC/AWAIT - Makes promises look synchronous (like Go without goroutines)
// =============================================================================

// Go style (blocking):
/*
func GetUser(id string) (*User, error) {
    user, err := database.FindUser(id)
    if err != nil {
        return nil, err
    }
    return user, nil
}
*/

// TypeScript async/await style:
async function getUser(id: string): Promise<{ name: string; email: string }> {
  try {
    const user = await fetchUserData(id); // Waits for completion
    return user;
  } catch (error) {
    throw new Error(`Failed to get user: ${error}`);
  }
}

// =============================================================================
// 3. ERROR HANDLING - Different patterns
// =============================================================================

// Go error handling:
/*
user, err := GetUser("123")
if err != nil {
    log.Printf("Error: %v", err)
    return
}
// Use user...
*/

// TypeScript error handling:
async function handleUserRequest(id: string): Promise<void> {
  try {
    const user = await getUser(id);
    console.log('User:', user);
  } catch (error) {
    console.error('Error:', error);
    // Error is handled here
  }
}

// =============================================================================
// 4. CONCURRENT OPERATIONS - Go vs TypeScript
// =============================================================================

// Go concurrent fetching with goroutines:
/*
func FetchMultipleUsers(ids []string) ([]User, error) {
    ch := make(chan UserResult, len(ids))
    
    for _, id := range ids {
        go func(userID string) {
            user, err := GetUser(userID)
            ch <- UserResult{User: user, Error: err}
        }(id)
    }
    
    var users []User
    for i := 0; i < len(ids); i++ {
        result := <-ch
        if result.Error != nil {
            return nil, result.Error
        }
        users = append(users, result.User)
    }
    return users, nil
}
*/

// TypeScript concurrent fetching with Promise.all:
async function fetchMultipleUsers(ids: string[]): Promise<Array<{ name: string; email: string }>> {
  try {
    // Start all requests concurrently (like launching goroutines)
    const promises = ids.map((id) => getUser(id));

    // Wait for all to complete (like reading from channels)
    const users = await Promise.all(promises);

    return users;
  } catch (error) {
    throw new Error(`Failed to fetch users: ${error}`);
  }
}

// =============================================================================
// 5. RACING OPERATIONS - First one wins
// =============================================================================

// Go select statement equivalent:
/*
select {
case result := <-primaryDB:
    return result
case result := <-backupDB:
    return result
case <-time.After(5 * time.Second):
    return errors.New("timeout")
}
*/

// TypeScript Promise.race:
async function fetchUserWithFallback(id: string): Promise<{ name: string; email: string }> {
  const primaryPromise = fetchUserData(id);
  const backupPromise = new Promise<{ name: string; email: string }>((resolve) => {
    setTimeout(() => resolve({ name: 'Backup User', email: 'backup@example.com' }), 2000);
  });
  const timeoutPromise = new Promise<never>((_, reject) => {
    setTimeout(() => reject(new Error('Timeout')), 5000);
  });

  // First promise to resolve/reject wins
  return Promise.race([primaryPromise, backupPromise, timeoutPromise]);
}

// =============================================================================
// 6. PRACTICAL PATTERNS FOR OUR GATEWAY
// =============================================================================

// Database operations (like your Go PostgreSQL code)
interface DatabaseConnection {
  query<T>(sql: string, params: any[]): Promise<T[]>;
  close(): Promise<void>;
}

// Service discovery async function
async function discoverServices(userID: string, db: DatabaseConnection): Promise<ServiceConfig[]> {
  try {
    const query = `
      SELECT id, service_slug, display_name, transport_type, mcp_server_url, auth_type, auth_config
      FROM user_service_configs 
      WHERE user_id = $1
    `;

    const results = await db.query<any>(query, [userID]);

    return results.map((row) => ({
      id: row.id,
      slug: row.service_slug,
      displayName: row.display_name,
      transportType: row.transport_type,
      mcpServerUrl: row.mcp_server_url,
      authType: row.auth_type,
      authConfig: JSON.parse(row.auth_config),
    }));
  } catch (error) {
    throw new Error(`Database error: ${error}`);
  }
}

// Multiple service connections (like your Go client management)
async function connectToServices(configs: ServiceConfig[]): Promise<Map<string, any>> {
  const connections = new Map();

  // Connect to all services concurrently
  const connectionPromises = configs.map(async (config) => {
    try {
      // This would create actual MCP client connections
      const client = await createMCPClient(config);
      connections.set(config.slug, client);
      return { slug: config.slug, success: true };
    } catch (error) {
      console.error(`Failed to connect to ${config.slug}:`, error);
      return { slug: config.slug, success: false, error };
    }
  });

  // Wait for all connection attempts
  const results = await Promise.allSettled(connectionPromises);

  // Log results
  results.forEach((result, index) => {
    if (result.status === 'fulfilled') {
      console.log(
        `Service ${configs[index].slug}: ${result.value.success ? 'Connected' : 'Failed'}`,
      );
    } else {
      console.error(`Service ${configs[index].slug}: Promise rejected:`, result.reason);
    }
  });

  return connections;
}

// Mock MCP client creation
async function createMCPClient(config: ServiceConfig): Promise<any> {
  // Simulate connection time
  await new Promise((resolve) => setTimeout(resolve, Math.random() * 1000));

  if (Math.random() > 0.8) {
    throw new Error('Connection failed');
  }

  return { id: config.id, connected: true };
}

// =============================================================================
// 7. KEY DIFFERENCES SUMMARY
// =============================================================================

/*
CONCURRENCY:
Go: Goroutines + Channels (true parallelism)
TypeScript: Promises + Event Loop (asynchronous, single-threaded)

ERROR HANDLING:
Go: Explicit error returns (user, err := GetUser())
TypeScript: try/catch blocks (try { await getUser() } catch (e) {})

TIMING:
Go: time.After(), select with timeout
TypeScript: Promise.race(), setTimeout()

COMMUNICATION:
Go: Channels for goroutine communication
TypeScript: Promises for async coordination

BLOCKING:
Go: Goroutines can block without affecting others
TypeScript: await blocks the current async function only
*/

// Export types and functions
interface ServiceConfig {
  id: string;
  slug: string;
  displayName: string;
  transportType: string;
  mcpServerUrl?: string;
  authType: string;
  authConfig: Record<string, any>;
}

export {
  fetchUserData,
  getUser,
  fetchMultipleUsers,
  fetchUserWithFallback,
  discoverServices,
  connectToServices,
  ServiceConfig,
  DatabaseConnection,
};
