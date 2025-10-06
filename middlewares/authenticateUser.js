const jwt = require('jsonwebtoken');

function authenticateUser(req, res, next) {
  try {
    const token = req.cookies.user_auth;
    if (!token) return res.status(401).json({ error: 'Unauthorized' });
    const payload = jwt.verify(token, process.env.JWT_SECRET || 'dev_secret');
    req.user = { id: payload.sub, email: payload.email };
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
}

module.exports = authenticateUser;
