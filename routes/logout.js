const express = require('express');
const router = express.Router();

// POST /auth/logout
router.post('/logout', (req, res) => {
  res.clearCookie('user_auth');
  res.clearCookie('admin_auth');
  res.clearCookie('auth');
  return res.json({ message: 'Logged out' });
});

module.exports = router;
