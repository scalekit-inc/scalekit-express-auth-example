const express = require('express');
const router = express.Router();
const { requireAuth } = require('../middleware/auth');

// Sessions management page
router.get('/', requireAuth, (req, res) => {
  const sessionInfo = {
    id: req.sessionID,
    created: req.session.cookie.originalMaxAge,
    expires: new Date(Date.now() + req.session.cookie.maxAge),
    user: req.session.user,
    tokens: {
      access_token_present: !!req.session.tokens?.access_token,
      refresh_token_present: !!req.session.tokens?.refresh_token,
      id_token_present: !!req.session.tokens?.id_token,
      expires_at: req.session.tokens?.expires_at ? 
        new Date(req.session.tokens.expires_at * 1000).toISOString() : null
    }
  };
  
  res.render('sessions', {
    title: 'Session Management',
    session: sessionInfo
  });
});

// Clear session (different from logout - doesn't call Scalekit logout)
router.post('/clear', requireAuth, (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Error clearing session:', err);
      return res.status(500).json({ error: 'Failed to clear session' });
    }
    res.redirect('/');
  });
});

module.exports = router;
