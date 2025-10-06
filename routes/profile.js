const express = require('express');
const router = express.Router();
const User = require('../models/User');
const authenticateUser = require('../middlewares/authenticateUser');

// Get user profile (including addresses)
router.get('/', authenticateUser, async (req, res) => {
	try {
		const user = await User.findOne({ email: req.user.email });
		if (!user) return res.status(404).json({ error: 'User not found' });
		return res.json({ user });
	} catch (err) {
		return res.status(500).json({ error: 'Failed to fetch profile' });
	}
});

// Update user profile (name, mobile, optionally addresses)
router.put('/', authenticateUser, async (req, res) => {
	try {
		const { name, mobile } = req.body;
		const user = await User.findOne({ email: req.user.email });
		if (!user) return res.status(404).json({ error: 'User not found' });
		if (name !== undefined) user.name = name;
		if (mobile !== undefined) user.mobile = mobile;
		await user.save();
		return res.json({ user });
	} catch (err) {
		return res.status(500).json({ error: 'Failed to update profile' });
	}
});


// Get single address
router.get('/address', authenticateUser, async (req, res) => {
	try {
		const user = await User.findOne({ email: req.user.email });
		if (!user) return res.status(404).json({ error: 'User not found' });
		return res.json({ address: user.address || null });
	} catch (err) {
		return res.status(500).json({ error: 'Failed to fetch address' });
	}
});

// Update or set single address
router.put('/address', authenticateUser, async (req, res) => {
	try {
		const user = await User.findOne({ email: req.user.email });
		if (!user) return res.status(404).json({ error: 'User not found' });
		const {
			doorNo = '',
			landmark = '',
			addressLine1 = '',
			addressLine2 = '',
			city = '',
			state = '',
			country = '',
			name = '',
			phone = ''
		} = req.body;
		const pincode = req.body.pincode || req.body.postalCode || '';
		user.address = {
			doorNo,
			landmark,
			addressLine1,
			addressLine2,
			city,
			state,
			pincode,
			country
		};
		if (name) user.name = name;
		if (phone) user.mobile = phone;
		await user.save();
		return res.json({ address: user.address, name: user.name, mobile: user.mobile });
	} catch (err) {
		return res.status(500).json({ error: 'Failed to update address' });
	}
});

module.exports = router;