const jwt = require('jsonwebtoken');
const User = require('../models/User');

async function authenticateAdmin(req, res, next) {
  try {
  const token = req.cookies.admin_auth;
    if (!token) return res.status(401).json({ error: 'Unauthorized' });
    const payload = jwt.verify(token, process.env.JWT_SECRET || 'dev_secret');
    // Check if user exists and is admin
    const user = await User.findOne({ email: payload.email });
    if (!user || user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    req.user = { id: payload.sub, email: payload.email, role: user.role };
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
}

module.exports = authenticateAdmin;
