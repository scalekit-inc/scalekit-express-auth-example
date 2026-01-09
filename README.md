# Express.js Scalekit Authentication Example

A simple Express.js app that shows how to add secure sign-in with Scalekit (OIDC). You can use it as a starting point or as a reference to integrate enterprise-grade authentication.

What this example includes:

- The app signs users in with Scalekit using the OpenID Connect (OIDC) authorization flow.
- Protected routes like `/dashboard` redirect unauthenticated users to the login flow.
- Cookie-based session management with secure HTTP-only cookies.
- Automatic token refresh when access tokens expire.
- Role-based and permission-based access control for protected resources.
- The templates use Bootstrap 5 classes so pages render well on desktop and mobile.
- After login, the dashboard displays user information, roles, permissions, and token data.
- Interactive permission testing widget to verify access controls.

## Prerequisites

- Node.js 16.x or later is installed.
- npm is installed.
- You have a Scalekit account with an OIDC application. [Sign up](https://app.scalekit.com/)

## 🛠️ Quick start

### Configure Scalekit

Pick one method below.

_Method A_ — .env file (recommended for local dev):

Create or update `.env` in the project root:

```env
# Replace placeholders with your values
SCALEKIT_ENV_URL=https://your-env.scalekit.dev
SCALEKIT_CLIENT_ID=YOUR_CLIENT_ID
SCALEKIT_CLIENT_SECRET=YOUR_CLIENT_SECRET
SCALEKIT_REDIRECT_URI=http://localhost:3000/auth/callback

# Optional server config
PORT=3000
NODE_ENV=development
```

_Method B_ — environment variables:

```bash
export SCALEKIT_ENV_URL=https://your-env.scalekit.dev
export SCALEKIT_CLIENT_ID=YOUR_CLIENT_ID
export SCALEKIT_CLIENT_SECRET=YOUR_CLIENT_SECRET
export SCALEKIT_REDIRECT_URI=http://localhost:3000/auth/callback
```

Important:

- Never commit secrets to source control.
- Ensure the redirect URI exactly matches what is configured in Scalekit.

### Build and run

```bash
# Install dependencies
npm install

# Run the application in development mode (with auto-reload)
npm run dev

# Or run in production mode
npm start
```

The application will start at `http://localhost:3000`

### Setup Scalekit

To find your required values:

1. Visit [Scalekit Dashboard](https://app.scalekit.com) and proceed to _Settings_

2. Copy the API credentials

   - **Environment URL** (e.g., `https://your-env.scalekit.dev`)
   - **Client ID**
   - **Client Secret** (You will need to generate a secret first)

3. Authentication > Redirect URLs > Allowed redirect URIs:
   - Add `http://localhost:3000/auth/callback` (no trailing slash)
   - Optionally add `http://localhost:3000` as a post-logout redirect

4. Configure roles and permissions (optional):
   - Go to **Roles & Permissions** in your Scalekit dashboard
   - Create roles (e.g., `admin`)
   - Create permissions (e.g., `settings:write`, `CreateContact`, `ReadContact`, etc.)
   - Assign permissions to roles
   - Assign roles to users or organizations

**Important for permissions to work:**
- Permissions assigned to roles in Scalekit will be included in the access token
- The app extracts permissions from the `permissions` claim in the access token
- Both standard (`permissions`) and namespaced (`https://scalekit.com/permissions`) claim formats are supported

### Application routes

| Route                   | Description                  | Auth required | Permission required |
| ----------------------- | ---------------------------- | ------------- | ------------------- |
| `/`                     | Home page with login option  | No            | None                |
| `/auth/login`           | Initiate OAuth login flow    | No            | None                |
| `/auth/callback`        | OIDC callback                | No            | None                |
| `/dashboard`            | Protected dashboard          | Yes           | None                |
| `/dashboard/admin`      | Admin panel                  | Yes           | `admin`             |
| `/dashboard/settings`   | Settings page                | Yes           | `settings:write`    |
| `/sessions`             | Session management           | Yes           | None                |
| `POST /sessions/clear`  | Clear session cookies        | Yes           | None                |
| `/logout`               | Logout and end session       | Yes           | None                |
| `/api/admin/users`      | Admin API (example)          | Yes           | `admin` role        |
| `POST /api/projects/create` | Create project API (example) | Yes       | `projects:create`   |

### 🚦 Try the app

1. Start the app (see Quick start)
2. Visit `http://localhost:3000`
3. Click Sign in with Scalekit
4. Authenticate with your provider
5. Open the dashboard to see:
   - Your user profile (given name, family name, email)
   - Your roles and permissions
   - Token information with expiration countdown
   - Interactive permission testing widget
6. Try accessing protected routes:
   - `/dashboard/admin` (requires `admin` permission)
   - `/dashboard/settings` (requires `settings:write` permission)
7. Test the permission widget by clicking "Test API" buttons
8. Visit `/sessions` to see session details
9. Click logout to end your session

Stuck? [Contact us](https://docs.scalekit.com/support/contact-us/).

## Code structure

```
express-scalekit-example/
├── views/                       # EJS templates
│   ├── index.ejs                # Home page
│   ├── dashboard.ejs            # User dashboard with permission testing
│   ├── admin.ejs                # Admin panel (requires admin permission)
│   ├── settings.ejs             # Settings page (requires settings:write)
│   └── sessions.ejs             # Session management page
├── server.js                    # Main application file
│   ├── Scalekit client initialization
│   ├── Authentication middleware
│   ├── Permission/role middleware
│   ├── Routes (auth, dashboard, sessions)
│   └── Cookie management
├── package.json                 # Dependencies and scripts
├── .env.example                 # Environment variables template
├── .gitignore
└── README.md                    # This file
```

## Dependencies

- **express** ^4.18.2 - Web framework
- **ejs** ^3.1.10 - Template engine
- **@scalekit-sdk/node** ^2.0.0 - Official Scalekit Node.js SDK
- **cookie-parser** ^1.4.6 - Cookie parsing middleware
- **dotenv** ^16.0.3 - Environment variable management

See `package.json` for exact versions.

## Authentication Flow

This application uses cookie-based session management with secure HTTP-only cookies:

1. **User clicks "Sign in"** → redirected to Scalekit authorization endpoint
2. **User authenticates** with their identity provider (SSO, social, magic link, passkey)
3. **Scalekit redirects back** to `/auth/callback` with authorization code
4. **App exchanges code for tokens** using `scalekit.authenticateWithCode()`
5. **Tokens stored in secure cookies**:
   - `access_token` - HTTP-only, secure cookie
   - `refresh_token` - HTTP-only, secure cookie
   - `id_token` - HTTP-only, secure cookie
6. **User profile extracted** from ID token (name, email, email_verified)
7. **Roles and permissions extracted** from access token
8. **User redirected to dashboard**

## Token Management

### Automatic Token Refresh

The authentication middleware automatically:
- Validates the access token on each request
- Detects expired tokens
- Uses the refresh token to get new tokens
- Updates cookies with refreshed tokens
- Extracts updated roles and permissions
- Maintains seamless user experience

### Security Features

- **HTTP-only cookies** - Prevents XSS attacks
- **Secure flag** - Requires HTTPS in production (via trust proxy)
- **Token validation** - Every request validates the access token
- **No server-side sessions** - Stateless authentication using JWT tokens
- **Automatic cleanup** - Expired cookies are cleared

## Roles & Permissions

### How It Works

1. **Configure in Scalekit Dashboard**:
   - Create roles (e.g., `admin`, `user`, `manager`)
   - Create permissions (e.g., `settings:write`, `CreateContact`, `DeleteContact`)
   - Assign permissions to roles
   - Assign roles to users

2. **Permissions in Tokens**:
   - Roles appear in both access token and ID token
   - Permissions appear in the access token's `permissions` claim
   - The app decodes the raw access token JWT to extract the `permissions` array

3. **Middleware Protection**:
   ```javascript
   // Require specific permission
   app.get('/dashboard/admin', authenticateToken, requirePermission('admin'), ...);

   // Require specific role
   app.get('/api/admin/users', authenticateToken, requireRole('admin'), ...);
   ```

### Permission Testing Widget

The dashboard includes an interactive widget to test permissions:
- Shows your current permissions and roles
- Test buttons for each permission
- Real-time API calls to protected endpoints
- Visual success/failure feedback
- Full JSON response display

## Scalekit SDK Methods Used

This application uses the official Scalekit Node.js SDK (`@scalekit-sdk/node`) for all authentication operations:

- `scalekit.getAuthorizationUrl()` - Generate OAuth authorization URL
- `scalekit.authenticateWithCode()` - Exchange code for tokens
- `scalekit.validateAccessToken()` - Validate access token
- `scalekit.token.refreshAccessToken()` - Refresh expired tokens

Additionally, the app directly decodes JWT tokens (access token and ID token) to extract:
- User profile data (from ID token)
- Roles and permissions (from access token)
- Token expiration times

## Enable debug logging

The application includes console logging for debugging:

```bash
# Console output shows:
✅ Authentication successful for user: user@example.com
✅ Extracted from access token - Roles: [ 'admin' ]
✅ Extracted from access token - Permissions: [ 'CreateContact', 'ReadContact', 'UpdateContact', 'DeleteContact', 'settings:write' ]
🔄 Access token expired, refreshing...
✅ Token refreshed successfully
```

To see full token payloads during development, the middleware includes debug logs showing the complete access token structure.

## Production Deployment

### Security Checklist

- [ ] Set `NODE_ENV=production`
- [ ] Use HTTPS (the app uses `trust proxy` setting for secure cookies behind proxies)
- [ ] Update `SCALEKIT_REDIRECT_URI` to production URL
- [ ] Never commit `.env` file to source control
- [ ] Use strong, random secrets
- [ ] Configure CORS if serving frontend separately
- [ ] Set up proper error monitoring
- [ ] Enable rate limiting on auth routes

### Cookie Configuration

The app sets secure cookie options automatically:
```javascript
res.cookie('access_token', token, {
  httpOnly: true,      // Prevents XSS
  secure: true,        // Requires HTTPS (in production)
  sameSite: 'lax',     // CSRF protection
  maxAge: 3600000      // 1 hour
});
```

## Troubleshooting

**Permissions not showing up?**
- Check Scalekit dashboard to verify permissions are assigned to your role
- Verify the role is assigned to your user
- Look at server console logs to see what's in the access token
- The app extracts permissions from the `permissions` claim in the access token payload

**"Cannot GET /login" error?**
- Use `/auth/login` instead (the app uses `/auth/login` as the login endpoint)

**Settings page error?**
- Ensure your user has the `settings:write` permission in Scalekit
- Check server logs for the full user profile data

**Token expiration issues?**
- The app automatically refreshes tokens when they expire
- Check server logs for refresh token errors
- Ensure your refresh token is valid and not revoked

## Support

- Read the Scalekit docs: [Documentation](https://docs.scalekit.com)
- Read the Express.js docs: [Documentation](https://expressjs.com)
- Contact Scalekit support: [Contact us](https://docs.scalekit.com/support/contact-us/)

## License 📄

This project is for demonstration and learning. Refer to dependency licenses for production use.
