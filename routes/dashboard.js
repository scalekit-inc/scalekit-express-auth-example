const express = require('express');
const router = express.Router();
const { requireAuth, requirePermission, requireAnyPermission } = require('../middleware/auth');

// Dashboard - requires authentication
router.get('/', requireAuth, (req, res) => {
  res.render('dashboard', {
    title: 'Dashboard',
    user: req.session.user,
    tokens: {
      access_token: req.session.tokens.access_token,
      refresh_token: req.session.tokens.refresh_token ? '****' : null,
      id_token: req.session.tokens.id_token ? '****' : null,
      expires_at: req.session.tokens.expires_at
    }
  });
});

// Admin section - requires 'admin' permission
router.get('/admin', requireAuth, requirePermission('admin'), (req, res) => {
  res.render('admin', {
    title: 'Admin Dashboard',
    user: req.session.user
  });
});

// Settings section - requires 'settings:write' permission
router.get('/settings', requireAuth, requirePermission('settings:write'), (req, res) => {
  res.render('settings', {
    title: 'Settings',
    user: req.session.user
  });
});

module.exports = router;
