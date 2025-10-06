const express = require('express');
const router = express.Router();
const User = require('../models/User');

// Middleware to authenticate user
const authenticateUser = require('../middlewares/authenticateUser');

// Get user's cart (from embedded array)
router.get('/', authenticateUser, async (req, res) => {
	try {
		const user = await User.findOne({ email: req.user.email });
		if (!user) return res.status(404).json({ error: 'User not found' });
		return res.json({ cart: user.cart || [] });
	} catch (err) {
		console.error('Get cart error:', err);
		return res.status(500).json({ error: 'Failed to get cart' });
	}
});

// Add item to cart (embedded array)
router.post('/', authenticateUser, async (req, res) => {
	try {
		const { product, quantity = 1 } = req.body;
		if (!product || !product.id || !product.name || !product.price || !product.image) {
			return res.status(400).json({ error: 'Invalid product data' });
		}
		const user = await User.findOne({ email: req.user.email });
		if (!user) return res.status(404).json({ error: 'User not found' });
		const existingItem = user.cart.find(item => item.id === product.id);
		if (existingItem) {
			existingItem.quantity += quantity;
		} else {
			user.cart.push({ ...product, quantity });
		}
		await user.save();
		return res.json({ message: 'Item added to cart' });
	} catch (err) {
		console.error('Add to cart error:', err);
		return res.status(500).json({ error: 'Failed to add to cart' });
	}
});

// Update cart item quantity (embedded array)
router.put('/:productId', authenticateUser, async (req, res) => {
	try {
		const { productId } = req.params;
		const { quantity } = req.body;
		if (!quantity || quantity < 1) {
			return res.status(400).json({ error: 'Invalid quantity' });
		}
		const user = await User.findOne({ email: req.user.email });
		if (!user) return res.status(404).json({ error: 'User not found' });
		const cartItem = user.cart.find(item => item.id === productId);
		if (!cartItem) {
			return res.status(404).json({ error: 'Item not found in cart' });
		}
		cartItem.quantity = quantity;
		await user.save();
		return res.json({ message: 'Cart item updated' });
	} catch (err) {
		console.error('Update cart error:', err);
		return res.status(500).json({ error: 'Failed to update cart' });
	}
});

// Remove item from cart (embedded array)
router.delete('/:productId', authenticateUser, async (req, res) => {
	try {
		const { productId } = req.params;
		const user = await User.findOne({ email: req.user.email });
		if (!user) return res.status(404).json({ error: 'User not found' });
		const initialLength = user.cart.length;
		user.cart = user.cart.filter(item => item.id !== productId);
		if (user.cart.length === initialLength) {
			return res.status(404).json({ error: 'Item not found in cart' });
		}
		await user.save();
		return res.json({ message: 'Item removed from cart' });
	} catch (err) {
		console.error('Remove from cart error:', err);
		return res.status(500).json({ error: 'Failed to remove from cart' });
	}
});

// Clear entire cart (embedded array)
router.delete('/', authenticateUser, async (req, res) => {
	try {
		const user = await User.findOne({ email: req.user.email });
		if (!user) return res.status(404).json({ error: 'User not found' });
		user.cart = [];
		await user.save();
		return res.json({ message: 'Cart cleared' });
	} catch (err) {
		console.error('Clear cart error:', err);
		return res.status(500).json({ error: 'Failed to clear cart' });
	}
});

module.exports = router;