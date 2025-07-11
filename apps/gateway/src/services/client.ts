import { ServiceConfig, AuthConfig } from '@/types/gateway';
import { Client } from '@modelcontextprotocol/sdk/client/index';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio';
import { StreamableHTTPTransport } from '@modelcontextprotocol/sdk/client/streamableHttp';
import * as fs from 'fs/promises';

interface CachedClient {
  client: Client;
  lastUsed: Date;
  userId: string;
  serviceSlug: string;
}

class ClientCache {
  private cache = new Map<string, CachedClient>();
  private locks = new Map<string, Promise<Client>>();

  async getOrCreateClient(
    userId: string,
    service: ServiceConfig,
    signal?: AbortSignal,
  ): Promise<Client> {
    const cacheKey = `${userId}:${service.slug}`;

    const cached = this.cache.get(cacheKey);
    if (cached) {
      try {
        await this.healthCheck(cached.client);
        cached.lastUsed = new Date();
        return cached.client;
      } catch (err) {
        console.log(`Cached client for ${cacheKey} failed health check`);
        this.cache.delete(cacheKey);
        await cached.client.close();
      }
    }

    if (this.locks.has(cacheKey)) {
      return await this.locks.get(cacheKey)!; // We know it exists from .has() check
    }

    const creationPromise = this.createClientForService(userId, service, signal);
    this.locks.set(cacheKey, creationPromise);

    try {
      const client = await creationPromise;
      this.cache.set(cacheKey, {
        client,
        lastUsed: new Date(),
        userId,
        serviceSlug: service.slug,
      });
      return client;
    } finally {
      this.locks.delete(cacheKey);
    }
  }

  private async healthCheck(client: Client): Promise<void> {
    const controller = new AbortController();
    setTimeout(() => controller.abort(), 2000);

    try {
      await Promise.race([
        client.listResources(),
        new Promise((_, reject) =>
          controller.signal.addEventListener('abort', () =>
            reject(new Error('Health check timeout')),
          ),
        ),
      ]);
    } catch (err) {
      throw new Error('Client health check failed');
    }
  }

  // Instantiates the correct MCP client based on the service's configuration.
  private async createClientForService(
    userId: string,
    service: ServiceConfig,
    signal?: AbortSignal,
  ): Promise<Client> {
    console.log(
      `Creating client for service ${service.displayName} (transport: ${service.transportType}, auth: ${service.authType})`,
    );

    if (service.transportType === 'sse' && service.authType === 'mcp_remote_managed') {
      console.log(`Handling mcp_remote_managed service ${service.displayName} via stdio`);

      let command: string[] = [];
      if (service.transportType === 'sse' && service.mcpServerUrl) {
        command = ['npx', '-y', 'mcp-remote', service.mcpServerUrl, '--host', 'localhost'];
      }
      if (command.length === 0) {
        throw new Error(`command generation failed for SEE service ${service.displayName}`);
      }

      const configDir = `/tmp/routekit_auth/user_${userId}_service_${service.slug}`;
      try {
        await fs.mkdir(configDir, { recursive: true });
      } catch (err: any) {
        throw new Error(`error creating client config directory: ${err}`);
      }

      const env: Record<string, string> = {
        MCP_REMOTE_CONFIG_DIR: configDir,
      };
      const cmdName = command[0];
      const args = command.slice(1);

      const transport = new StdioClientTransport({
        command: cmdName,
        args,
        env,
      });

      const client = new Client({
        name: 'routekit-gateway',
        version: '1.0.0',
      });

      await client.connect(transport);
      return client;
    }

    if (service.transportType === 'streamable-http') {
      if (!service.mcpServerUrl) {
        throw new Error(`missing mcp_server_url for remote service ${service.displayName}`);
      }

      let urlToConnect = service.mcpServerUrl;
      const headers: Record<string, string> = {};
      const authConfig = service.authConfig;

      switch (service.authType) {
        case 'pat':
          if (!authConfig.token) {
            throw new Error(
              `{"action_required": "user_authentication", "service_name": "${service.displayName}", "auth_type": "pat"}`,
            );
          }
          headers['Authorization'] = `Bearere ${authConfig.token}`;
          break;

        case 'api_key_in_header':
          if (!authConfig.headerName || !authConfig.apiKey) {
            throw new Error(`missing header name or API key for service ${service.displayName}`);
          }
          headers[authConfig.headerName] = authConfig.apiKey;
          break;

        case 'api_key_in_url':
          if (!authConfig.queryParamName || !authConfig.apiKey) {
            throw new Error(
              `missing query param name or API key for service ${service.displayName}`,
            );
          }
          const url = new URL(urlToConnect);
          url.searchParams.set(authConfig.queryParamName, authConfig.apiKey);
          urlToConnect = url.toString();
          break;

        case 'no_auth':
          break;

        default:
          throw new Error(
            `unsupported auth type ${service.authType} for remote service ${service.displayName}`,
          );
      }

      const transport = new StreamableHTTPTransport({
        url: urlToConnect,
        headers,
      });

      const client = new Client({
        name: 'routekit-gateway',
        version: '1.0.0',
      });

      await client.connect(transport);
      return client;
    }

    throw new Error(`unsupported or unhandled transport type: ${service.transportType}`);
  }
}

export const clientCache = new ClientCache();
