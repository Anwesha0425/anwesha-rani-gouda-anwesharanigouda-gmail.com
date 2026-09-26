// Route registration. First match wins — register specific paths before parameterised ones.
// /members/me must come before /members/:userId
// /invites/:token (public) is registered directly (not under /orgs/:org)

import { registerAuthRoutes } from './auth.js';
import { registerOrgRoutes } from './orgs.js';
import { registerMemberRoutes } from './members.js';
import { registerDeviceRoutes } from './devices.js';
import { registerSessionRoutes } from './sessions.js';

export function registerRoutes(router, deps) {
  const { db, secret } = deps;

  // Auth routes (login and refresh are public; token and me are authenticated)
  registerAuthRoutes(router, { db, secret });

  // Org routes
  registerOrgRoutes(router, { db, secret });

  // Member + invite routes
  // Register /members/me BEFORE /members/:userId so 'me' is not captured as a userId
  registerMemberRoutes(router, { db, secret });

  // Device + grant routes
  registerDeviceRoutes(router, { db, secret });

  // Session + effective + audit routes
  registerSessionRoutes(router, { db, secret });
}
