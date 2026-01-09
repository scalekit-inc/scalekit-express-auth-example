// Middleware to check if user is authenticated
const requireAuth = (req, res, next) => {
  if (!req.session.user || !req.session.tokens) {
    return res.redirect('/login');
  }
  next();
};

// Middleware to check if user has specific permission
const requirePermission = (permission) => {
  return (req, res, next) => {
    if (!req.session.user) {
      return res.redirect('/login');
    }
    
    const userPermissions = req.session.user.permissions || [];
    
    if (!userPermissions.includes(permission)) {
      return res.status(403).render('error', {
        title: 'Access Denied',
        error: `You don't have the required permission: ${permission}`
      });
    }
    
    next();
  };
};

// Middleware to check if user has specific role
const requireRole = (role) => {
  return (req, res, next) => {
    if (!req.session.user) {
      return res.redirect('/login');
    }
    
    const userRoles = req.session.user.roles || [];
    
    if (!userRoles.includes(role)) {
      return res.status(403).render('error', {
        title: 'Access Denied',
        error: `You don't have the required role: ${role}`
      });
    }
    
    next();
  };
};

// Middleware to check if user has any of the specified permissions
const requireAnyPermission = (permissions) => {
  return (req, res, next) => {
    if (!req.session.user) {
      return res.redirect('/login');
    }
    
    const userPermissions = req.session.user.permissions || [];
    const hasPermission = permissions.some(p => userPermissions.includes(p));
    
    if (!hasPermission) {
      return res.status(403).render('error', {
        title: 'Access Denied',
        error: `You don't have any of the required permissions: ${permissions.join(', ')}`
      });
    }
    
    next();
  };
};

module.exports = {
  requireAuth,
  requirePermission,
  requireRole,
  requireAnyPermission
};
