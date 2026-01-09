// server.js - Express app with Scalekit cookie-based session management
const express = require('express');
const cookieParser = require('cookie-parser');
const { Scalekit } = require('@scalekit-sdk/node');

// Environment configuration
require('dotenv').config();
const requiredEnvVars = [
  'SCALEKIT_ENV_URL',
  'SCALEKIT_CLIENT_ID',
  'SCALEKIT_CLIENT_SECRET',
  'SCALEKIT_REDIRECT_URI'
];

// Validate required environment variables
const missingVars = requiredEnvVars.filter(varName => !process.env[varName]);
if (missingVars.length > 0) {
  console.error('❌ Missing required environment variables:', missingVars.join(', '));
  process.exit(1);
}

// Initialize Scalekit client
const scalekit = new Scalekit(
  process.env.SCALEKIT_ENV_URL,
  process.env.SCALEKIT_CLIENT_ID,
  process.env.SCALEKIT_CLIENT_SECRET
);

const app = express();
const PORT = process.env.PORT || 3000;

// View engine setup
app.set('view engine', 'ejs');
app.set('views', './views');

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Trust proxy for secure cookies behind reverse proxy
app.set('trust proxy', 1);

// ============================================================================
// AUTHENTICATION MIDDLEWARE
// ============================================================================

/**
 * Middleware to validate access token and refresh if expired
 * This implements Scalekit's recommended session management approach
 */
async function authenticateToken(req, res, next) {
  try {
    const accessToken = req.cookies.access_token;
    const refreshToken = req.cookies.refresh_token;

    // No tokens = not authenticated
    if (!accessToken) {
      return res.redirect('/auth/login');
    }

    try {
      // Validate access token using Scalekit SDK
      const tokenPayload = await scalekit.validateAccessToken(accessToken);

      // Decode the raw access token to get roles and permissions
      let roles = [];
      let permissions = [];

      try {
        const accessTokenDecoded = JSON.parse(Buffer.from(accessToken.split('.')[1], 'base64').toString());
        roles = accessTokenDecoded.roles || [];
        permissions = accessTokenDecoded.permissions || [];
        console.log('✅ Extracted from access token - Roles:', roles);
        console.log('✅ Extracted from access token - Permissions:', permissions);
      } catch (e) {
        console.warn('⚠️  Could not decode raw access token:', e.message);
      }

      // Token is valid - attach user info to request
      req.user = {
        id: tokenPayload.sub,
        family_name: tokenPayload.family_name,
        given_name: tokenPayload.given_name,
        email: tokenPayload.email,
        organizationId: tokenPayload.oid,
        roles: roles,
        permissions: permissions
      };

      return next();
      
    } catch (error) {
      // Access token expired or invalid - try to refresh
      if (refreshToken) {
        try {
          console.log('🔄 Access token expired, refreshing...');

          // Use Scalekit SDK to refresh the token
          const tokens = await scalekit.token.refreshAccessToken({
            refreshToken: refreshToken
          });

          // Set new tokens in cookies
          setAuthCookies(res, tokens);

          // Validate the new access token
          const tokenPayload = await scalekit.validateAccessToken(tokens.accessToken);

          // Decode the raw refreshed access token to get roles and permissions
          let roles = [];
          let permissions = [];

          try {
            const accessTokenDecoded = JSON.parse(Buffer.from(tokens.accessToken.split('.')[1], 'base64').toString());
            roles = accessTokenDecoded.roles || [];
            permissions = accessTokenDecoded.permissions || [];
            console.log('✅ Extracted from refreshed access token - Roles:', roles);
            console.log('✅ Extracted from refreshed access token - Permissions:', permissions);
          } catch (e) {
            console.warn('⚠️  Could not decode refreshed access token:', e.message);
          }

          req.user = {
            id: tokenPayload.sub,
            email: tokenPayload.email,
            organizationId: tokenPayload.oid,
            roles: roles,
            permissions: permissions
          };

          console.log('✅ Token refreshed successfully');
          return next();
          
        } catch (refreshError) {
          console.error('❌ Token refresh failed:', refreshError.message);
          clearAuthCookies(res);
          return res.redirect('/auth/login');
        }
      } else {
        // No refresh token available
        clearAuthCookies(res);
        return res.redirect('/auth/login');
      }
    }
  } catch (error) {
    console.error('❌ Authentication middleware error:', error);
    clearAuthCookies(res);
    return res.redirect('/auth/login');
  }
}

/**
 * Middleware to check if user has required permission
 */
function requirePermission(permission) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Not authenticated' });
    }
    
    if (!req.user.permissions.includes(permission)) {
      return res.status(403).json({ 
        error: 'Forbidden',
        message: `Missing required permission: ${permission}`
      });
    }
    
    next();
  };
}

/**
 * Middleware to check if user has required role
 */
function requireRole(role) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Not authenticated' });
    }
    
    if (!req.user.roles.includes(role)) {
      return res.status(403).json({ 
        error: 'Forbidden',
        message: `Missing required role: ${role}`
      });
    }
    
    next();
  };
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * Set authentication cookies with secure settings
 * This implements Scalekit's recommended cookie security
 */
function setAuthCookies(res, tokens) {
  const isProduction = process.env.NODE_ENV === 'production';
  
  const cookieOptions = {
    httpOnly: true,        // Prevents JavaScript access (XSS protection)
    secure: isProduction,  // HTTPS only in production
    sameSite: 'lax',      // CSRF protection
    path: '/'
  };
  
  // Set access token (short-lived, 5 min default)
  res.cookie('access_token', tokens.accessToken, {
    ...cookieOptions,
    maxAge: 5 * 60 * 1000 // 5 minutes in milliseconds
  });
  
  // Set refresh token (long-lived)
  res.cookie('refresh_token', tokens.refreshToken, {
    ...cookieOptions,
    maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days in milliseconds
  });
  
  // Set ID token for user info display
  if (tokens.idToken) {
    res.cookie('id_token', tokens.idToken, {
      ...cookieOptions,
      maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days in milliseconds
    });
  }
}

/**
 * Clear all authentication cookies
 */
function clearAuthCookies(res) {
  res.clearCookie('access_token', { path: '/' });
  res.clearCookie('refresh_token', { path: '/' });
  res.clearCookie('id_token', { path: '/' });
}

// ============================================================================
// ROUTES
// ============================================================================

// Home page (public)
app.get('/', (req, res) => {
  res.render('index', {
    title: 'Home',
    user: null
  });
});

// Initiate login (redirects to Scalekit)
app.get('/auth/login', (req, res) => {
  try {
    const method = req.query.method || 'default';
    
    // Build scopes based on auth method
    let scopes = ['openid', 'profile', 'email', 'offline_access'];
    
    // Build authorization URL with Scalekit
    const authorizationUrl = scalekit.getAuthorizationUrl(
      process.env.SCALEKIT_REDIRECT_URI,
      {
        scopes: scopes,
        // Optional: pass connection_id for direct SSO, social provider, etc.
        state: JSON.stringify({ method, timestamp: Date.now() })
      }
    );
    
    console.log('🔐 Redirecting to Scalekit for authentication...');
    res.redirect(authorizationUrl);
    
  } catch (error) {
    console.error('❌ Login error:', error);
    res.status(500).send('Login failed: ' + error.message);
  }
});

// OAuth callback (handles code exchange)
app.get('/auth/callback', async (req, res) => {
  try {
    const { code, error, error_description } = req.query;
    
    // Handle OAuth errors
    if (error) {
      console.error('❌ OAuth error:', error, error_description);
      return res.redirect('/auth/login?error=' + encodeURIComponent(error_description || error));
    }
    
    if (!code) {
      console.error('❌ No authorization code received');
      return res.redirect('/auth/login?error=no_code');
    }
    
    console.log('🔄 Exchanging authorization code for tokens...');
    
    // Exchange code for tokens using Scalekit SDK
    const result = await scalekit.authenticateWithCode(
      code,
      process.env.SCALEKIT_REDIRECT_URI
    );
    
    console.log('✅ Authentication successful for user:', result.user.email);
    
    // Set secure cookies with tokens
    setAuthCookies(res, {
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
      idToken: result.idToken
    });
    
    // Redirect to dashboard
    res.redirect('/dashboard');
    
  } catch (error) {
    console.error('❌ Callback error:', error);
    res.redirect('/auth/login?error=' + encodeURIComponent('Authentication failed'));
  }
});

// Dashboard (protected route)
app.get('/dashboard', authenticateToken, async (req, res) => {
  // Decode ID token to get full user profile
  let userProfile = {
    id: req.user.id,
    email: req.user.email,
    roles: req.user.roles,
    permissions: req.user.permissions
  };

  try {
    const idToken = req.cookies.id_token;
    if (idToken) {
      // Decode ID token (already validated by middleware)
      const decoded = JSON.parse(Buffer.from(idToken.split('.')[1], 'base64').toString());
      userProfile = {
        id: req.user.id,
        email: decoded.email,
        given_name: decoded.given_name,
        family_name: decoded.family_name,
        picture: decoded.picture,
        organizationName: decoded.org_name,
        email_verified: decoded.email_verified,
        roles: req.user.roles,
        permissions: req.user.permissions
      };
    }
  } catch (error) {
    console.warn('⚠️  Could not decode ID token:', error.message);
  }

  // Get tokens for display and extract expiration time from access token
  let expiresAt = null;
  try {
    const accessToken = req.cookies.access_token;
    if (accessToken) {
      const tokenParts = accessToken.split('.');
      if (tokenParts.length === 3) {
        const payload = JSON.parse(Buffer.from(tokenParts[1], 'base64').toString());
        expiresAt = payload.exp; // This is a Unix timestamp in seconds
      }
    }
  } catch (error) {
    console.warn('⚠️  Could not decode access token for expiration:', error.message);
  }

  const tokens = {
    access_token: req.cookies.access_token || '',
    refresh_token: req.cookies.refresh_token || null,
    id_token: req.cookies.id_token || null,
    expires_at: expiresAt
  };

  res.render('dashboard', {
    title: 'Dashboard',
    user: userProfile,
    tokens: tokens
  });
});

// Admin Dashboard (requires admin permission)
app.get('/dashboard/admin', authenticateToken, requirePermission('admin'), async (req, res) => {
  let userProfile = {
    id: req.user.id,
    email: req.user.email,
    roles: req.user.roles,
    permissions: req.user.permissions
  };

  try {
    const idToken = req.cookies.id_token;
    if (idToken) {
      const decoded = JSON.parse(Buffer.from(idToken.split('.')[1], 'base64').toString());
      userProfile = {
        id: req.user.id,
        email: decoded.email,
        name: decoded.given_name + ' ' + decoded.family_name,
        given_name: decoded.given_name,
        family_name: decoded.family_name,
        picture: decoded.picture,
        email_verified: decoded.email_verified,
        roles: req.user.roles,
        permissions: req.user.permissions
      };
    }
  } catch (error) {
    console.warn('⚠️  Could not decode ID token:', error.message);
  }

  res.render('admin', {
    title: 'Admin',
    user: userProfile
  });
});

// Settings page (requires settings:write permission)
app.get('/dashboard/settings', authenticateToken, requirePermission('settings:write'), async (req, res) => {
  console.log('🔍 req.user in settings:', req.user);

  let userProfile = {
    id: req.user?.id || 'unknown',
    email: req.user?.email || 'unknown',
    roles: req.user?.roles || [],
    permissions: req.user?.permissions || []
  };

  try {
    const idToken = req.cookies.id_token;
    if (idToken) {
      const decoded = JSON.parse(Buffer.from(idToken.split('.')[1], 'base64').toString());
      userProfile = {
        id: decoded.sub || req.user?.id || 'unknown',
        email: decoded.email,
        name: (decoded.given_name && decoded.family_name) ? decoded.given_name + ' ' + decoded.family_name : decoded.email,
        given_name: decoded.given_name,
        family_name: decoded.family_name,
        picture: decoded.picture,
        email_verified: decoded.email_verified,
        roles: req.user?.roles || [],
        permissions: req.user?.permissions || []
      };
    }
  } catch (error) {
    console.warn('⚠️  Could not decode ID token:', error.message);
  }

  console.log('🔍 userProfile in settings:', userProfile);

  res.render('settings', {
    title: 'Settings',
    user: userProfile
  });
});

// Sessions page
app.get('/sessions', authenticateToken, async (req, res) => {
  let userProfile = {
    id: req.user.id,
    email: req.user.email,
    roles: req.user.roles,
    permissions: req.user.permissions
  };

  try {
    const idToken = req.cookies.id_token;
    if (idToken) {
      const decoded = JSON.parse(Buffer.from(idToken.split('.')[1], 'base64').toString());
      userProfile = {
        id: req.user.id,
        email: decoded.email,
        name: decoded.given_name + ' ' + decoded.family_name,
        given_name: decoded.given_name,
        family_name: decoded.family_name,
        picture: decoded.picture,
        email_verified: decoded.email_verified,
        roles: req.user.roles,
        permissions: req.user.permissions
      };
    }
  } catch (error) {
    console.warn('⚠️  Could not decode ID token:', error.message);
  }

  // Calculate session expiry from access token
  let expiresAt = null;
  try {
    const accessToken = req.cookies.access_token;
    if (accessToken) {
      const tokenPayload = JSON.parse(Buffer.from(accessToken.split('.')[1], 'base64').toString());
      expiresAt = new Date(tokenPayload.exp * 1000).toLocaleString();
    }
  } catch (error) {
    console.warn('⚠️  Could not decode access token:', error.message);
  }

  res.render('sessions', {
    title: 'Sessions',
    user: userProfile,
    session: {
      id: req.user.id,
      user: userProfile,
      expires: expiresAt || 'Unknown',
      tokens: {
        access_token_present: !!req.cookies.access_token,
        refresh_token_present: !!req.cookies.refresh_token,
        id_token_present: !!req.cookies.id_token,
        expires_at: expiresAt
      }
    }
  });
});

// Clear session (POST)
app.post('/sessions/clear', (req, res) => {
  clearAuthCookies(res);
  res.redirect('/');
});

// Protected API route (requires specific role)
app.get('/api/admin/users', authenticateToken, requireRole('admin'), (req, res) => {
  // Return the actual logged-in user's information
  res.json({
    message: 'Admin access granted',
    currentUser: {
      id: req.user.id,
      email: req.user.email,
      roles: req.user.roles,
      permissions: req.user.permissions
    }
  });
});

// Protected API route (requires specific permission)
app.post('/api/projects/create', authenticateToken, requirePermission('projects:create'), (req, res) => {
  res.json({
    message: 'Project created successfully',
    project: {
      id: Math.floor(Math.random() * 1000),
      name: 'New Project',
      createdBy: req.user.email
    }
  });
});

// Logout
app.get('/logout', (req, res) => {
  console.log('👋 User logging out');

  // Clear authentication cookies
  clearAuthCookies(res);

  // Redirect to home page
  res.redirect('/?message=logged_out');
});

// Keep legacy /auth/logout for backward compatibility
app.get('/auth/logout', (req, res) => {
  res.redirect('/logout');
});

// Error handler
app.use((err, req, res, next) => {
  console.error('❌ Error:', err);
  res.status(500).json({ 
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// Start server
app.listen(PORT, () => {
  console.log('✅ Server started successfully');
  console.log(`🚀 Listening on http://localhost:${PORT}`);
  console.log(`📝 Scalekit Environment: ${process.env.SCALEKIT_ENV_URL}`);
  console.log('\n🔐 Session Management Features:');
  console.log('   ✅ Secure HTTP-only cookies');
  console.log('   ✅ Automatic token refresh via middleware');
  console.log('   ✅ Role-based access control');
  console.log('   ✅ Permission validation');
  console.log('   ✅ No session storage required\n');
});

module.exports = app;