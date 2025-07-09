import 'dotenv/config';
import { Pool } from 'pg';
import { ServiceConfig, ServiceConfigRow } from '@/types/gateway';

const pool = new Pool();

import { decrypt } from '@/pkg/crypto/encryption'; // Import the decrypt function

function decryptAuthConfig(encryptedConfig: string | null, encryptionKey: string): Record<string, any> {
  if (!encryptedConfig) {
    return {};
  }

  try {
    const decryptedJsonString = decrypt(encryptedConfig, encryptionKey);
    return JSON.parse(decryptedJsonString);
  } catch (error) {
    console.error('Failed to decrypt or parse auth config:', error);
    return {};
  }
}

export async function getServiceConfigsForUser(userId: string): Promise<ServiceConfig[]> {
  const query = `
    SELECT 
      id, 
      user_id, 
      service_slug, 
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
    const { rows } = await pool.query<ServiceConfigRow>(query, [userId]);
    return rows.map((row) => ({
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
    }));
  } catch (error) {
    console.error('Error fetching service configurations:', error);
    throw new Error('Could not retrieve service configurations from the database.');
  }
}

export async function closeDbConnection(): Promise<void> {
  await pool.end();
}
