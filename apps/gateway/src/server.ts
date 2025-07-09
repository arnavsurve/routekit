import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import { closeDbConnection } from '@/services/discovery';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp';

const app = express();

const mcpServer = new McpServer({
  name: 'routekit-gateway',
  version: '1.0.0',
});

const transports = new Map<string, StreamableHTTPServerTransport>();

const PORT = process.env.PORT || 8080;
const HOST = process.env.HOST || '0.0.0.0';

app.use(express.json());
app.use(cors());

app.get('/health', (req, res) => {
  res.status(200).send('Gateway is healthy!');
});

const server = app.listen(PORT, () => {
  console.log(`Gateway server listening on http://${HOST}:${PORT}`);
});

process.on('SIGTERM', async () => {
  console.log('SIGTERM signal received: closing HTTP server');
  server.close(async () => {
    console.log('HTTP server closed.');
    await closeDbConnection();
    console.log('Database connection closed.');
    process.exit(0);
  });
});

process.on('SIGINT', async () => {
  console.log('SIGINT signal received: closing HTTP server');
  server.close(async () => {
    console.log('HTTP server closed.');
    await closeDbConnection();
    console.log('Database connection closed.');
    process.exit(0);
  });
});

