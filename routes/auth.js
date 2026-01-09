const express = require('express');
const router = express.Router();
const scalekitClient = require('../config/scalekitClient');
const crypto = require('crypto');

// Login page
router.get('/login', (req, res) => {
  // If already authenticated, redirect to dashboard
  if (req.session.user) {
    return res.redirect('/dashboard');
  }
  
  res.render('login', { title: 'Login' });
});

// Initiate OAuth flow
router.post('/login', (req, res) => {
  try {
    // Generate state for CSRF protection
    const state = crypto.randomBytes(32).toString('hex');
    req.session.oauthState = state;
    
    // Get authorization URL
    const authUrl = scalekitClient.getAuthorizationUrl(
      process.env.SCALEKIT_REDIRECT_URI,
      {
        state,
        // You can add connection_id or organization_id here if needed
        // connection_id: req.body.connection_id,
        // organization_id: req.body.organization_id
      }
    );
    
    res.redirect(authUrl);
  } catch (error) {
    console.error('Error initiating login:', error);
    res.render('error', {
      title: 'Login Error',
      error: 'Failed to initiate login. Please try again.'
    });
  }
});

// OAuth callback
router.get('/callback', async (req, res) => {
  try {
    const { code, state, error, error_description } = req.query;
    
    // Check for OAuth errors
    if (error) {
      console.error('OAuth error:', error, error_description);
      return res.render('error', {
        title: 'Authentication Error',
        error: error_description || 'Authentication failed'
      });
    }
    
    // Verify state to prevent CSRF
    if (state !== req.session.oauthState) {
      return res.render('error', {
        title: 'Security Error',
        error: 'Invalid state parameter. Possible CSRF attack.'
      });
    }
    
    // Clear the state from session
    delete req.session.oauthState;
    
    // Exchange code for tokens
    const result = await scalekitClient.authenticateWithCode(
      code,
      process.env.SCALEKIT_REDIRECT_URI
    );
    
    // Store tokens in session
    req.session.tokens = {
      access_token: result.access_token,
      refresh_token: result.refresh_token,
      id_token: result.id_token,
      expires_at: Math.floor(Date.now() / 1000) + (result.expires_in || 3600)
    };
    
    // Validate token and get user claims
    const claims = await scalekitClient.validateToken(result.access_token);
    
    // Store user information in session
    req.session.user = {
      id: claims.sub,
      email: claims.email,
      name: claims.name || claims.email,
      email_verified: claims.email_verified,
      permissions: claims.permissions || [],
      roles: claims.roles || [],
      metadata: claims.metadata || {}
    };
    
    // Save session and redirect
    req.session.save((err) => {
      if (err) {
        console.error('Session save error:', err);
      }
      res.redirect('/dashboard');
    });
    
  } catch (error) {
    console.error('Callback error:', error);
    res.render('error', {
      title: 'Authentication Error',
      error: 'Failed to complete authentication. Please try again.'
    });
  }
});

module.exports = router;
