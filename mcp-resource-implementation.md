# MCP Resource Implementation Brain Dump

## Current State Analysis

### What We Discovered
1. **GitHub MCP Server is Working Correctly**: The "unsupported resource type" error is the server correctly saying "this is a resource, not a tool"
2. **Our Implementation is Fighting the Spec**: We've been trying to hack around proper MCP behavior instead of embracing it
3. **Agent Never Actually Read Files Before**: Previous "success" was getting content through alternative tools (PR files, issues, etc.)

### The Core Issue
Different MCP operations serve different purposes:
- **Tools** (`callTool`) - For actions: search, create, update, delete
- **Resources** (`readResource`) - For reading content: files, documents, data

GitHub MCP server implements this correctly:
- `github__search_repositories` = Tool ✅ 
- `github__list_issues` = Tool ✅
- `github__get_file_contents` = Resource ❌ (we were calling it as a tool)

## What We Implemented

### Gateway Meta Tools
1. `routekit_get_connected_services` - Lists available services
2. `routekit_get_service_tools` - Lists tools from services  
3. `routekit_execute` - Executes tools
4. `routekit_list_resources` - Lists resources from services
5. `routekit_read_resource` - Reads specific resources

### Current Problems
1. **Automatic Fallback Hack**: Complex logic trying to convert failed tool calls to resource calls
2. **Provider-Specific Code**: Hardcoded GitHub logic instead of generic patterns
3. **Agent Confusion**: Doesn't know when to use tools vs resources
4. **Inconsistent Workflow**: Sometimes uses proper resource workflow, sometimes doesn't

## The Clean Solution (Option 2)

### 1. Remove All Hacks
- Remove automatic tool→resource fallback logic in `routekit_execute`
- Clean error messages when tools fail with "unsupported resource type"
- No provider-specific hardcoded logic

### 2. Clear Separation of Concerns
**Tools** (via `routekit_execute`):
- Actions and operations
- Searching, creating, updating
- Returns structured data or confirmation

**Resources** (via `routekit_list_resources` + `routekit_read_resource`):
- Reading file contents
- Accessing documents/data
- Returns actual content

### 3. Improved Agent Workflow
Update system prompt to be crystal clear:
```
FOR ACTIONS (search, create, update):
1. routekit_get_service_tools
2. routekit_execute

FOR READING CONTENT (files, documents):
1. routekit_list_resources  
2. routekit_read_resource
```

### 4. Better Error Handling
When `routekit_execute` fails with "unsupported resource type":
```
Error: This appears to be a resource, not a tool. 
To read content, use:
1. routekit_list_resources to find available resources
2. routekit_read_resource to read specific content
```

## Implementation Steps

### Step 1: Clean Up Gateway
1. Remove automatic fallback hack from `handleExecute`
2. Remove `generateResourceURIs` function (if we added it)
3. Add clear error message for "unsupported resource type"

### Step 2: Fix Agent Guidance  
1. Update system prompt for clear tools vs resources workflow
2. Add examples of when to use each approach
3. Remove confusing guidance about automatic fallbacks

### Step 3: Test Both Workflows
1. **Tool workflow**: Search repositories, list issues, etc.
2. **Resource workflow**: List available files, read specific files

### Step 4: Commit Clean Checkpoint
- Tools work for actions
- Resources work for content
- Clear separation of concerns
- No hacks or workarounds

## Expected Behavior After Cleanup

### Successful Tool Usage (Actions)
```
User: "Show me issues in arnavsurve/routekit"
Agent: routekit_execute("github__list_issues", {owner: "arnavsurve", repo: "routekit"})
Result: ✅ List of issues
```

### Successful Resource Usage (Content)
```
User: "Read the README file"
Agent: 
1. routekit_list_resources(["github"])
2. routekit_read_resource("github://repos/arnavsurve/routekit/contents/README.md")
Result: ✅ File contents
```

### Clear Error for Wrong Approach
```
Agent tries: routekit_execute("github__get_file_contents", ...)
Result: ❌ "This is a resource, not a tool. Use routekit_list_resources + routekit_read_resource"
```

## Benefits of Clean Implementation

1. **Follows MCP Spec**: Proper tools vs resources separation
2. **Provider Agnostic**: No hardcoded service-specific logic
3. **Clear Workflow**: Agent knows exactly when to use what
4. **Maintainable**: Simple, clean code without hacks
5. **Extensible**: Easy to add new services that follow the same patterns

## Files to Modify

1. `/Users/asurve/dev/routekit/apps/gateway/main.go`
   - Remove fallback logic from `handleExecute`
   - Add clear error messaging

2. `/Users/asurve/dev/routekit/apps/web/backend/agent/handler.go`
   - Update system prompt for clarity
   - Remove any hack-related code

## Implementation Status: ✅ COMPLETE

### ✅ Step 1: Gateway Cleanup
- Removed automatic fallback hack from `handleExecute`
- Added clear error message: "'toolname' is a resource, not a tool. Use: 1) routekit_list_resources, 2) routekit_read_resource"
- No more provider-specific hardcoded logic

### ✅ Step 2: System Prompt Update  
- Added guidance: "If a tool call fails with 'is a resource, not a tool', use the resource workflow instead"
- Clear separation between tools (actions) and resources (content)
- Explicit workflow instructions for both approaches

### ✅ Step 3: Build Success
- Clean compilation with no errors
- Ready for testing and commit

## Next Steps

1. ✅ **Clean checkpoint achieved** - Ready to commit
2. **Test the workflows:**
   - Tool workflow: `routekit_execute` for actions (search, list, create)
   - Resource workflow: `routekit_list_resources` → `routekit_read_resource` for content
3. **Revisit remaining issues** with fresh understanding

## Why This Approach Wins

- **Embraces MCP spec** instead of fighting it
- **Clean codebase** ready for future enhancements
- **Clear workflows** that make sense to agents and developers
- **Foundation** for proper multi-provider support