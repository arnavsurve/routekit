import 'dotenv/config';
import { Pool } from 'pg';
import { ServiceConfig, ServiceConfigRow, ToolsResponse } from '@/types/gateway';
import { Tool } from '@modelcontextprotocol/sdk/types.js';
import { decrypt } from '@/pkg/crypto/encryption';
import { clientCache } from '@/services/client';

const dbPool = new Pool();

function decryptAuthConfig(
  encryptedConfig: string | null,
  encryptionKey: string,
): Record<string, any> {
  if (!encryptedConfig) {
    return {};
  }

  try {
    const decryptedJsonString = decrypt(encryptedConfig, encryptionKey);
    return JSON.parse(decryptedJsonString);
  } catch (err) {
    console.error('Failed to decrypt or parse auth config:', err);
    return {};
  }
}

export async function getServiceConfigsForUser(userId: string): Promise<ServiceConfig[]> {
  const query = `
    SELECT 
      id, 
      user_id, 
      service_slug, 
      display_name,
      transport_type, 
      mcp_server_url, 
      auth_type, 
      auth_config_encrypted,
      scopes, 
      audience
    FROM user_service_configs 
    WHERE user_id = $1
  `;

  try {
    const { rows } = await dbPool.query<ServiceConfigRow>(query, [userId]);
    return rows.map(
      (row) =>
        ({
          id: row.id,
          userId: row.user_id,
          slug: row.service_slug,
          displayName: row.display_name,
          transportType: row.transport_type as any,
          mcpServerUrl: row.mcp_server_url ?? undefined,
          authType: row.auth_type as any,
          authConfig: decryptAuthConfig(row.auth_config_encrypted, process.env.ENCRYPTION_KEY!),
          scopes: row.scopes ? JSON.parse(row.scopes) : [],
          audience: row.audience ?? undefined,
        }) as ServiceConfig,
    );
  } catch (err) {
    console.error('Error fetching service configurations:', err);
    throw new Error('Could not retrieve service configurations from the database.');
  }
}

export async function getServiceToolsForUser(
  userId: string,
  services: ServiceConfig[],
): Promise<ToolsResponse> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 30_000);

  let firstActionErr: Error | null = null;

  const toolArrays = await Promise.all(
    services.map(async (service): Promise<Tool[]> => {
      if (controller.signal.aborted) return [];

      try {
        const client = await clientCache.getOrCreateClient(userId, service, controller.signal);
        if (!client) {
          throw new Error(`Failed to create client for service ${service.slug}`);
        }
        const res = await client.listTools();
        return res.tools.map((tool) => ({
          ...tool,
          name: `${service.slug}__${tool.name}`,
        }));
      } catch (err: any) {
        const msg = err.message ?? String(err);

        if (msg.includes('action_required')) {
          if (!firstActionErr) firstActionErr = err;
        } else {
          console.warn(
            `discoverUserTools: failed listing tools from ${service.displayName}: ${err}`,
          );
          // TODO: Implement cache eviction + transport cleanup
          // ... do we still need a client cache in this implementation?
          // does the typescript mcp sdk cover the mcp client auth struggles we
          // faced that caused us to shell out to mcp-remote?
          // clientCache.delete(`${userId}:${service.slug}`);

          // For now, just log the error - transport cleanup will be handled by client management
          console.warn(`Service ${service.slug} will need client cleanup`);
        }
      }

      return [];
    }),
  );

  clearTimeout(timeout);

  if (controller.signal.aborted) {
    console.error('discoverUserTools: timed out after 30s');
    throw firstActionErr ?? new Error('Tool discovery timed out');
  }

  if (firstActionErr) {
    throw firstActionErr;
  }

  const tools = ([] as Tool[]).concat(...toolArrays);
  return {
    tools: tools,
  };
}

export async function closeDbConnection(): Promise<void> {
  await dbPool.end();
}
