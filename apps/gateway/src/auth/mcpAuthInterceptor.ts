import { CallToolRequest, CallToolResult } from '@modelcontextprotocol/sdk/types';
import jwt from 'jsonwebtoken';
import { AppContext } from '../server';

export interface JwtClaims extends jwt.JwtPayload {
  userId: string;
}

export interface AuthenticatedAppContext extends AppContext {
  userId: string;
}

// Extracts the JWT from the request data, validates it,
// and injects the userId into AppContext for downstream handlers.
export async function mcpAuthInterceptor(
  req: CallToolRequest,
  context: AppContext,
  next: (req: CallToolRequest, context: AuthenticatedAppContext) => Promise<CallToolResult>,
): Promise<CallToolResult> {
  const token = req.params._meta?.jwt;

  if (typeof token !== 'string' || !token) {
    return {
      content: [
        {
          type: 'text',
          text: 'Missing or invalid authentication token in request meta.',
        },
      ],
      isError: true,
    };
  }

  let claims: JwtClaims;
  try {
    claims = jwt.verify(token, context.env.JWT_SECRET) as JwtClaims;
  } catch (err) {
    const message = err instanceof jwt.JsonWebTokenError ? err.message : 'Invalid token';
    return {
      content: [
        {
          type: 'text',
          text: `Authentication error: ${message}`,
        },
      ],
      isError: true,
    };
  }

  if (!claims.userId) {
    return {
      content: [
        {
          type: 'text',
          text: 'Authentication error: invalid claims, userId is missing.',
        },
      ],
      isError: true,
    };
  }

  const authenticatedContext: AuthenticatedAppContext = {
    ...context,
    userId: claims.userId,
  };

  return next(req, authenticatedContext);
}
