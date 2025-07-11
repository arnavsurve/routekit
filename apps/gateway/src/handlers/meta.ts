import { AuthenticatedAppContext } from '@/auth/mcpAuthInterceptor';
import { getServiceConfigsForUser, getServiceToolsForUser } from '@/services/discovery';
import { ServiceConfig, ServiceInfo, ToolsResponse } from '@/types/gateway';
import { CallToolRequest, CallToolResult } from '@modelcontextprotocol/sdk/types';

export async function handleGetConfiguredServices(
  userId: string,
): Promise<{ services: ServiceInfo[] }> {
  try {
    const configs = await getServiceConfigsForUser(userId);

    const serviceInfos: ServiceInfo[] = configs.map((cfg) => ({
      service_slug: cfg.slug,
      display_name: cfg.displayName,
    }));

    return { services: serviceInfos };
  } catch (err) {
    console.error('Error getting connected services:', err);
    throw new Error('Could not get connected services for user.');
  }
}

export async function handleGetServiceTools(
  req: CallToolRequest,
  context: AuthenticatedAppContext,
): Promise<CallToolResult> {
  const services = req.params.services as string[];
  if (services.length < 1) {
    return {
      content: [
        {
          type: 'text',
          text: 'Error: services must be an array of strings with non-zero length.',
        },
      ],
      isError: true,
    };
  }

  try {
    const userConfigs: ServiceConfig[] = await getServiceConfigsForUser(context.userId);

    const configMap: Record<string, ServiceConfig> = {};
    userConfigs.forEach((cfg) => {
      configMap[cfg.slug] = cfg;
    });

    const targetServices: ServiceConfig[] = services
      .filter((slug) => {
        if (!configMap[slug]) {
          console.warn(
            `getServiceTools: user ${context.userId} asked for "${slug}" but it's not in their config.`,
          );
          return false;
        }
        return true;
      })
      .map((slug) => configMap[slug]);

    const discoveredTools: ToolsResponse = await getServiceToolsForUser(
      context.userId,
      targetServices,
    );

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(discoveredTools),
        },
      ],
      isError: false,
    };
  } catch (err) {
    console.error(`Error discovering tools for services ${services}: ${err}`);
    return {
      content: [
        {
          type: 'text',
          text: `Error: ${err}`,
        },
      ],
      isError: true,
    };
  }
}
