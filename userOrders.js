// backend/userOrders.js

const express = require('express');
const router = express.Router();
const User = require('./models/User');

// CORS is applied globally in index.js; avoid setting per-router CORS to prevent duplicate headers


// Get orders for a specific user (from embedded array)
const Order = require('./models/Order');
router.get('/:email', async (req, res) => {
  try {
    const { email } = req.params;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: 'User not found' });
    // Only use valid ObjectIds in user.orders array
    const orderIds = (user.orders || []).filter(
      (id) => (typeof id === 'string' && id.match(/^[a-f0-9]{24}$/i)) || (id && id._bsontype === 'ObjectId')
    );
    
    // Populate orders from Order collection
    const orders = await Order.find({ _id: { $in: orderIds } }).sort({ createdAt: -1 });
    
    return res.json({ orders });
  } catch (err) {
    console.error('Get user orders error:', err);
    return res.status(500).json({ error: 'Failed to get user orders' });
  }
});

module.exports = router;
