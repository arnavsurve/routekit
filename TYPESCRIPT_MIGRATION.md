# RouteKit Gateway: Go to TypeScript Migration Plan

## Executive Summary

Migrate the RouteKit Gateway from Go (`mcp-go` library) to TypeScript using the official MCP SDK to solve current protocol compliance issues and improve maintainability.

## Current Issues with Go Implementation

### Protocol Compliance Problems
- **"Unsupported resource type" errors**: mcp-go library has parsing issues with resource-formatted responses
- **Limited resource support**: Community library vs official first-party TypeScript SDK
- **Protocol version lag**: mcp-go may not support latest MCP specification features

### Development Challenges
- **Limited documentation**: Sparse examples and community support for mcp-go
- **Complex error handling**: Manual parsing of MCP error responses 
- **Resource workflow hacks**: Current implementation requires workarounds for proper resource support
- **Debugging difficulty**: Limited tooling for MCP protocol debugging in Go

### Library Maturity
- **mcp-go**: Community library, limited active development
- **TypeScript SDK**: Official Anthropic/MCP foundation library, 8.4k stars, active development

## Benefits of TypeScript Migration

### Technical Advantages
- ✅ **First-party MCP support**: Official SDK with guaranteed protocol compliance
- ✅ **Built-in resource handling**: Native `listResources`/`readResource` support
- ✅ **Session management**: Built-in HTTP session handling with cleanup
- ✅ **Type safety**: Full TypeScript types for MCP protocol
- ✅ **Better error handling**: Comprehensive error types and messages
- ✅ **MCP Inspector integration**: Official debugging tools

### Operational Benefits
- ✅ **Faster development**: Rich documentation and examples
- ✅ **Community support**: Large, active TypeScript/Node.js ecosystem
- ✅ **Testing tools**: Built-in testing utilities and mocking
- ✅ **Performance**: V8 engine optimizations for JSON/HTTP workloads

## Migration Architecture

### Current Go Architecture
```
RouteKit Gateway (Go)
├── main.go                 # HTTP server, MCP server setup
├── auth middleware         # JWT validation  
├── service discovery       # PostgreSQL queries
├── client management       # Connection pooling/caching
├── tool routing           # Tool execution via mcp-go
└── resource routing       # Resource access via mcp-go
```

### Target TypeScript Architecture  
```
RouteKit Gateway (TypeScript)
├── server.ts              # Express + MCP SDK setup
├── auth/                  # JWT middleware
│   └── middleware.ts
├── services/             # Service management
│   ├── discovery.ts      # PostgreSQL service configs
│   └── clients.ts        # MCP client management  
├── handlers/             # MCP request handlers
│   ├── tools.ts          # Tool execution
│   ├── resources.ts      # Resource access
│   └── meta.ts           # Meta tools (routekit_*)
└── types/                # TypeScript interfaces
    └── config.ts
```

## Component Migration Map

| Go Component | TypeScript Equivalent | Migration Complexity |
|--------------|----------------------|---------------------|
| `main.go` HTTP server | Express.js + MCP SDK | **Low** - Standard Express patterns |
| JWT auth middleware | Custom Express middleware | **Low** - Port existing logic |
| PostgreSQL client | `pg` library | **Low** - Similar query patterns |
| MCP server setup | `McpServer` class | **Medium** - New SDK patterns |
| Tool routing | `server.registerTool()` | **Medium** - Different handler signatures |
| Resource routing | `server.registerResource()` | **Medium** - New resource patterns |
| Client management | SDK session management | **High** - Complete redesign |
| Error handling | SDK error types | **Medium** - New error patterns |

## Migration Phases

### Phase 1: Foundation (Day 1)
- [ ] Set up TypeScript project structure
- [ ] Configure Express.js server
- [ ] Implement JWT authentication middleware  
- [ ] Set up PostgreSQL connection with `pg`
- [ ] Create basic MCP server with health check

**Success Criteria**: Server starts, auth works, database connects

### Phase 2: Meta Tools (Day 2)
- [ ] Implement `routekit_get_connected_services`
- [ ] Implement `routekit_get_service_tools`  
- [ ] Implement `routekit_execute` (basic tool routing)
- [ ] Add service discovery and client management
- [ ] Test basic tool execution workflow

**Success Criteria**: Can list services, discover tools, execute simple tools

### Phase 3: Resources & Polish (Day 3)
- [ ] Implement `routekit_list_resources`
- [ ] Implement `routekit_read_resource`
- [ ] Add comprehensive error handling
- [ ] Performance optimization and caching
- [ ] Integration testing with existing frontend

**Success Criteria**: Full feature parity with Go implementation

### Phase 4: Deployment (Day 4)
- [ ] Update Docker configuration
- [ ] Update CI/CD pipelines
- [ ] Production deployment and monitoring
- [ ] Documentation updates

**Success Criteria**: Production ready, monitoring in place

## Technical Implementation Details

### Dependencies
```json
{
  "dependencies": {
    "@modelcontextprotocol/sdk": "^1.15.0",
    "express": "^4.18.0",
    "pg": "^8.11.0",
    "jsonwebtoken": "^9.0.0",
    "cors": "^2.8.5",
    "zod": "^3.22.0"
  },
  "devDependencies": {
    "@types/node": "^20.0.0",
    "@types/express": "^4.17.0",
    "@types/pg": "^8.10.0",
    "typescript": "^5.0.0",
    "tsx": "^4.0.0"
  }
}
```

### Core Server Setup
```typescript
import express from 'express';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';

const app = express();
const server = new McpServer({
  name: "routekit-gateway",
  version: "1.0.0"
});

// Register meta tools
server.registerTool("routekit_execute", {...}, handleExecute);
server.registerTool("routekit_list_resources", {...}, handleListResources);

// Session management
const transports = new Map<string, StreamableHTTPServerTransport>();

app.post('/mcp', async (req, res) => {
  // Handle streamable HTTP with session management
});
```

### Service Client Management
```typescript
class ServiceClientManager {
  private clients = new Map<string, McpClient>();
  
  async getClient(userID: string, serviceConfig: ServiceConfig): Promise<McpClient> {
    const key = `${userID}:${serviceConfig.slug}`;
    
    if (this.clients.has(key)) {
      return this.clients.get(key)!;
    }
    
    // Create new client based on transport type
    const client = await this.createClient(serviceConfig);
    this.clients.set(key, client);
    return client;
  }
}
```

## API Compatibility

### Maintained Endpoints
- `POST /mcp` - Main MCP endpoint (with session management)
- All existing meta tools with same signatures
- Same authentication flow (JWT in request meta)
- Same database schema and service configurations

### Enhanced Features
- Better error messages with specific guidance
- Improved resource support following MCP spec
- Built-in session management and cleanup
- MCP Inspector compatibility for debugging

## Database Schema

**No changes required** - existing PostgreSQL schema for `user_service_configs` remains compatible.

## Deployment Strategy

### Docker Updates
```dockerfile
FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY dist/ ./dist/
EXPOSE 8080
CMD ["node", "dist/server.js"]
```

### Environment Variables
Same as current Go implementation:
- `JWT_SECRET`
- `DATABASE_URL` 
- `ENCRYPTION_KEY`

## Risk Mitigation

### Compatibility Risks
- **Frontend integration**: Maintain exact API compatibility
- **Service configurations**: Ensure all transport types work
- **Authentication flow**: Preserve JWT handling

### Mitigation Strategies
- Comprehensive integration tests
- Gradual rollout with feature flags
- Rollback plan to Go implementation
- Monitoring and alerting during transition

## Testing Strategy

### Unit Tests
- Meta tool handlers
- Service discovery logic
- Authentication middleware
- Client management

### Integration Tests  
- Full MCP workflow (connect → list tools → execute)
- Resource workflow (list → read)
- Multi-user session management
- Error handling scenarios

### Performance Tests
- Concurrent client connections
- Tool execution latency
- Memory usage under load
- Session cleanup efficiency

## Success Metrics

### Technical Metrics
- **Error reduction**: Eliminate "unsupported resource type" errors
- **Response time**: <100ms for meta tool operations
- **Resource usage**: <512MB memory, <1% CPU at idle
- **Reliability**: 99.9% uptime

### Developer Experience
- **Development speed**: 50% faster feature development
- **Debugging**: Built-in MCP Inspector support
- **Documentation**: Comprehensive examples and guides
- **Testing**: 90%+ code coverage

## Rollback Plan

If migration fails:
1. **Immediate**: Switch DNS/load balancer to Go service
2. **Short-term**: Fix critical issues in Go implementation
3. **Long-term**: Re-evaluate migration approach

**Rollback triggers**:
- >5% error rate increase
- >50ms latency increase  
- Any authentication failures
- Frontend integration breaks

## Timeline Summary

| Phase | Duration | Key Deliverables |
|-------|----------|------------------|
| Foundation | 1 day | Basic server + auth |
| Meta Tools | 1 day | Tool execution working |
| Resources | 1 day | Full feature parity |
| Deployment | 1 day | Production ready |
| **Total** | **4 days** | **Complete migration** |

## Next Steps

1. **Approval**: Review and approve migration plan
2. **Setup**: Create TypeScript project structure  
3. **Development**: Begin Phase 1 implementation
4. **Testing**: Comprehensive integration testing
5. **Deployment**: Gradual production rollout

---

**Migration Lead**: [Developer Name]
**Timeline**: 4 days
**Risk Level**: Medium (well-established migration path)
**Business Impact**: High (resolves current protocol issues)
