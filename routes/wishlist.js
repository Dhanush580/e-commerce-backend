const express = require('express');
const router = express.Router();
const User = require('../models/User');
const authenticateUser = require('../middlewares/authenticateUser');

// Get user's wishlist (from embedded array)
router.get('/', authenticateUser, async (req, res) => {
	try {
		const user = await User.findOne({ email: req.user.email });
		if (!user) return res.status(404).json({ error: 'User not found' });
		return res.json({ wishlist: user.wishlist || [] });
	} catch (err) {
		console.error('Get wishlist error:', err);
		return res.status(500).json({ error: 'Failed to get wishlist' });
	}
});

// Add item to wishlist (embedded array)
router.post('/', authenticateUser, async (req, res) => {
	try {
		const { product } = req.body;
		if (!product || !product.id || !product.name || !product.price || !product.image) {
			return res.status(400).json({ error: 'Invalid product data' });
		}
		const user = await User.findOne({ email: req.user.email });
		if (!user) return res.status(404).json({ error: 'User not found' });
		const exists = user.wishlist.some(item => item.id === product.id);
		if (exists) {
			return res.status(400).json({ error: 'Product already in wishlist' });
		}
		user.wishlist.push(product);
		await user.save();
		return res.json({ message: 'Item added to wishlist' });
	} catch (err) {
		console.error('Add to wishlist error:', err);
		return res.status(500).json({ error: 'Failed to add to wishlist' });
	}
});

// Remove item from wishlist (embedded array)
router.delete('/:productId', authenticateUser, async (req, res) => {
	try {
		const { productId } = req.params;
		const user = await User.findOne({ email: req.user.email });
		if (!user) return res.status(404).json({ error: 'User not found' });
		const initialLength = user.wishlist.length;
		user.wishlist = user.wishlist.filter(item => item.id !== productId);
		if (user.wishlist.length === initialLength) {
			return res.status(404).json({ error: 'Item not found in wishlist' });
		}
		await user.save();
		return res.json({ message: 'Item removed from wishlist' });
	} catch (err) {
		console.error('Remove from wishlist error:', err);
		return res.status(500).json({ error: 'Failed to remove from wishlist' });
	}
});

// Clear entire wishlist (embedded array)
router.delete('/', authenticateUser, async (req, res) => {
	try {
		const user = await User.findOne({ email: req.user.email });
		if (!user) return res.status(404).json({ error: 'User not found' });
		user.wishlist = [];
		await user.save();
		return res.json({ message: 'Wishlist cleared' });
	} catch (err) {
		console.error('Clear wishlist error:', err);
		return res.status(500).json({ error: 'Failed to clear wishlist' });
	}
});

module.exports = router;