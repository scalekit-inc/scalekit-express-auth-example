const { ScalekitClient } = require('@scalekit-sdk/node');

// Initialize Scalekit client
const scalekitClient = new ScalekitClient(
  process.env.SCALEKIT_ENV_URL,
  process.env.SCALEKIT_CLIENT_ID,
  process.env.SCALEKIT_CLIENT_SECRET
);

// Helper function to get authorization URL
const getAuthorizationUrl = (redirectUri, state = null, codeChallenge = null) => {
  const options = {
    redirectUri: redirectUri || process.env.SCALEKIT_REDIRECT_URI,
  };
  
  if (state) {
    options.state = state;
  }
  
  if (codeChallenge) {
    options.codeChallenge = codeChallenge;
    options.codeChallengeMethod = 'S256';
  }
  
  return scalekitClient.getAuthorizationUrl(
    process.env.SCALEKIT_REDIRECT_URI,
    options
  );
};

// Helper function to exchange code for tokens
const authenticateWithCode = async (code, redirectUri = null) => {
  try {
    const result = await scalekitClient.authenticateWithCode(
      code,
      redirectUri || process.env.SCALEKIT_REDIRECT_URI
    );
    return result;
  } catch (error) {
    console.error('Authentication error:', error);
    throw error;
  }
};

// Helper function to validate token and get claims
const validateToken = async (accessToken) => {
  try {
    const claims = await scalekitClient.validateAccessToken(accessToken);
    return claims;
  } catch (error) {
    console.error('Token validation error:', error);
    throw error;
  }
};

// Helper function to refresh token
const refreshToken = async (refreshToken) => {
  try {
    const result = await scalekitClient.refreshAccessToken(refreshToken);
    return result;
  } catch (error) {
    console.error('Token refresh error:', error);
    throw error;
  }
};

// Helper function to get logout URL
const getLogoutUrl = (idToken = null) => {
  const postLogoutRedirectUri = process.env.SCALEKIT_POST_LOGOUT_REDIRECT_URI || 
                                 process.env.SCALEKIT_REDIRECT_URI?.replace('/auth/callback', '');
  
  return scalekitClient.getLogoutUrl({
    idTokenHint: idToken,
    postLogoutRedirectUri
  });
};

module.exports = {
  scalekitClient,
  getAuthorizationUrl,
  authenticateWithCode,
  validateToken,
  refreshToken,
  getLogoutUrl
};
