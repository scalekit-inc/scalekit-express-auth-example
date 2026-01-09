# Express.js Scalekit Authentication - Quick Start Guide

## What You Have

A complete Express.js application that replicates the Django example with:

✅ OAuth 2.0 / OIDC authentication flow
✅ Social logins, magic links, and passkeys support
✅ Automatic token refresh middleware
✅ Role-based and permission-based access control
✅ Session management
✅ Protected routes
✅ Same UI/UX as Django example (Bootstrap 5)

## Permissions Demo

The app demonstrates 2 permissions:
- `admin` - Access to `/dashboard/admin`
- `settings:write` - Access to `/dashboard/settings`

## Setup in 5 Steps

1. **Install dependencies**
   ```bash
   npm install
   ```

2. **Configure Scalekit**
   - Copy `.env.example` to `.env`
   - Fill in your Scalekit credentials from dashboard
   ```env
   SCALEKIT_ENV_URL=https://your-env.scalekit.io
   SCALEKIT_CLIENT_ID=your_client_id
   SCALEKIT_CLIENT_SECRET=your_client_secret
   SCALEKIT_REDIRECT_URI=http://localhost:3000/auth/callback
   ```

3. **Set redirect URL in Scalekit Dashboard**
   - Go to Scalekit Dashboard → Authentication → Redirect URLs
   - Add: `http://localhost:3000/auth/callback`

4. **Run the app**
   ```bash
   npm run dev
   ```

5. **Test**
   - Visit: http://localhost:3000
   - Click "Sign in with Scalekit"
   - Authenticate and explore!

## Key Files

- `server.js` - Main application with token refresh middleware
- `config/scalekitClient.js` - Scalekit SDK configuration
- `middleware/auth.js` - Authentication & permission middleware
- `routes/auth.js` - Login and OAuth callback
- `routes/dashboard.js` - Protected routes with permissions
- `routes/sessions.js` - Session management
- `views/*.ejs` - Bootstrap 5 UI templates

## Routes

| URL | Auth? | Permission | Description |
|-----|-------|-----------|-------------|
| `/` | No | - | Home page |
| `/auth/login` | No | - | Login page |
| `/auth/callback` | No | - | OAuth callback |
| `/dashboard` | Yes | - | User dashboard |
| `/dashboard/admin` | Yes | `admin` | Admin panel |
| `/dashboard/settings` | Yes | `settings:write` | Settings |
| `/sessions` | Yes | - | Session management |
| `/logout` | Yes | - | Logout |

## Features Checklist

✅ OAuth 2.0 / OIDC login flow with Scalekit
✅ Social Logins, Magic links, Passkeys (via Scalekit)
✅ User session management
✅ Token validation and refresh
✅ Permissions + Roles (admin, settings:write)
✅ Protected routes/endpoints
✅ Session management UI
✅ Permission-based middleware logic
✅ Logout functionality
✅ Responsive Bootstrap UI
✅ Error handling

## Testing Permissions

To test the permission-protected routes:

1. In Scalekit Dashboard, assign permissions to your test user:
   - Add `admin` permission
   - Add `settings:write` permission

2. Login to the app

3. Try accessing:
   - `/dashboard/admin` (requires `admin`)
   - `/dashboard/settings` (requires `settings:write`)

Without permissions, you'll see "Access Denied" errors.

## Production Deployment

Before deploying:

1. Set `NODE_ENV=production`
2. Use strong `SESSION_SECRET`
3. Configure production session store (Redis/MongoDB)
4. Enable HTTPS and secure cookies
5. Update redirect URIs to production URLs
6. Set up monitoring and logging

## Need Help?

- Check `README.md` for detailed documentation
- [Scalekit Docs](https://docs.scalekit.com)
- [Scalekit Support](https://docs.scalekit.com/support/contact-us/)

## Differences from Django Example

The Express version has the same functionality but uses:
- Express.js instead of Django
- EJS templates instead of Django templates
- express-session instead of Django sessions
- @scalekit-sdk/node instead of scalekit-sdk-python

The UI and user experience are identical!
