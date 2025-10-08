
const express = require('express');
const router = express.Router();
const Product = require('../models/Product');
const Order = require('../models/Order');
const authenticateAdmin = require('../middlewares/authenticateAdmin');
const upload = require('../config/multer');
const { uploadBuffer } = require('../utils/gridfs');

// Admin dashboard analytics (total orders, etc)
router.get('/dashboard', authenticateAdmin, async (req, res) => {
	try {
		const totalOrders = await Order.countDocuments();
		// You can add more analytics here if needed
		return res.json({ analytics: { totalOrders } });
	} catch (err) {
		console.error('Admin dashboard analytics error:', err);
		return res.status(500).json({ error: 'Failed to fetch dashboard analytics' });
	}
});

// Multiple image upload endpoint (Admin only)
router.post('/upload-images', authenticateAdmin, upload.array('images', 10), async (req, res) => {
	try {
		if (!req.files || req.files.length === 0) {
			return res.status(400).json({ error: 'No image files provided' });
		}
			// Save to GridFS and return relative /images/:id URLs
			const ids = [];
		for (const file of req.files) {
			const id = await uploadBuffer(file.buffer, file.originalname, file.mimetype);
			ids.push(id);
		}
			const imageUrls = ids.map(id => `/images/${id}`);
		res.json({
			success: true,
			imageUrls: imageUrls,
			ids,
		});
	} catch (error) {
		console.error('Image upload error:', error);
		res.status(500).json({ error: 'Failed to upload images' });
	}
});

// Single image upload (Admin only) - for edit flow compatibility
router.post('/upload-image', authenticateAdmin, upload.single('image'), async (req, res) => {
	try {
		if (!req.file) {
			return res.status(400).json({ error: 'No image file provided' });
		}
		const id = await uploadBuffer(req.file.buffer, req.file.originalname, req.file.mimetype);
			const imageUrl = `/images/${id}`;
		return res.json({ success: true, imageUrl, id });
	} catch (error) {
		console.error('Single image upload error:', error);
		return res.status(500).json({ error: 'Failed to upload image' });
	}
});

// Helper to normalize incoming image URLs before storing
function normalizeIncomingImages(images, req) {
	const baseUrl = (process.env.PUBLIC_BASE_URL || `${req.protocol}://${req.get('host')}`).replace(/\/$/, '');
	return (images || []).map((u) => {
		if (typeof u !== 'string') return u;
		// If relative /images or /uploads keep as is
		if (u.startsWith('/images/') || u.startsWith('/uploads/')) return u;
		// If bare ObjectId, convert to /images/:id
		if (/^[a-f\d]{24}$/i.test(u)) return `/images/${u}`;
		// If absolute http(s) to our own base with /images, strip base
		try {
			const url = new URL(u);
			if ((baseUrl.startsWith(url.origin)) && url.pathname.startsWith('/images/')) {
				return url.pathname;
			}
		} catch {}
		// Otherwise keep original (could be external CDN or data URL)
		return u;
	});
}

// Add new product (Admin only)
router.post('/products', authenticateAdmin, async (req, res) => {
	try {
		const { productId, name, images, price, category, subCategory, description, inStock } = req.body || {};
		if (!productId || !name || !images || !Array.isArray(images) || images.length === 0 || !price || !category || !description) {
			return res.status(400).json({ error: 'All fields are required' });
		}
		const existing = await Product.findOne({ productId });
		if (existing) {
			return res.status(409).json({ error: 'Product ID already exists' });
		}
		const product = await Product.create({
			productId,
			name,
				images: normalizeIncomingImages(images, req),
			price,
			category,
			subCategory: subCategory || null,
			description,
			inStock: inStock !== undefined ? inStock : true,
		});
		return res.status(201).json({ message: 'Product added', product });
	} catch (err) {
		console.error('Add product error:', err);
		return res.status(500).json({ error: 'Failed to add product' });
	}
});

// Get all products (Admin only, with optional filters)
router.get('/products', authenticateAdmin, async (req, res) => {
	   try {
		   let { category, subCategory, page = 1, limit = 10, search = '' } = req.query;
		   page = parseInt(page) > 0 ? parseInt(page) : 1;
		   limit = parseInt(limit) > 0 ? parseInt(limit) : 10;
		   let query = {};
		   if (category && category !== 'all') {
			   query.category = category;
		   }
		   if (subCategory && subCategory !== 'all') {
			   query.subCategory = subCategory;
		   }
		   if (search && search.trim() !== '') {
			   const regex = new RegExp(search.trim(), 'i');
			   query.$or = [
				   { name: regex },
				   { productId: regex },
				   { category: regex },
				   { subCategory: regex }
			   ];
		   }
		   const [products, total] = await Promise.all([
			   Product.find(query)
				   .sort({ createdAt: -1 })
				   .skip((page - 1) * limit)
				   .limit(limit)
				   .select('productId name images price category subCategory description inStock createdAt updatedAt'),
			   Product.countDocuments(query)
		   ]);
		   return res.json({
			   products,
			   pagination: {
				   page,
				   limit,
				   total,
				   pages: Math.ceil(total / limit),
				   hasNext: page * limit < total,
				   hasPrev: page > 1,
			   },
		   });
	   } catch (err) {
		   console.error('Get admin products error:', err);
		   return res.status(500).json({ error: 'Failed to fetch products' });
	   }
});

// Update product (Admin only)
router.put('/products/:productId', authenticateAdmin, async (req, res) => {
	try {
		const { productId } = req.params;
		const { name, images, price, category, subCategory, description, inStock } = req.body || {};
		const product = await Product.findOne({ productId });
		if (!product) {
			return res.status(404).json({ error: 'Product not found' });
		}
		if (name !== undefined) product.name = name;
		if (images !== undefined) product.images = normalizeIncomingImages(images, req);
		if (price !== undefined) product.price = price;
		if (category !== undefined) product.category = category;
		if (subCategory !== undefined) product.subCategory = subCategory || null;
		if (description !== undefined) product.description = description;
		if (inStock !== undefined) product.inStock = inStock;
		product.updatedAt = new Date();
		await product.save();
		return res.json({ message: 'Product updated', product });
	} catch (err) {
		console.error('Update product error:', err);
		return res.status(500).json({ error: 'Failed to update product' });
	}
});

// Delete product (Admin only)
router.delete('/products/:productId', authenticateAdmin, async (req, res) => {
	try {
		const { productId } = req.params;
		const product = await Product.findOneAndDelete({ productId });
		if (!product) {
			return res.status(404).json({ error: 'Product not found' });
		}
		return res.json({ message: 'Product deleted' });
	} catch (err) {
		console.error('Delete product error:', err);
		return res.status(500).json({ error: 'Failed to delete product' });
	}
});

// Product stats (Admin only)
router.get('/products/stats', authenticateAdmin, async (req, res) => {
	try {
		const totalProducts = await Product.countDocuments();
		const inStockProducts = await Product.countDocuments({ inStock: true });
		const outOfStockProducts = await Product.countDocuments({ inStock: false });
		const categoryStats = await Product.aggregate([
			{ $group: { _id: '$category', count: { $sum: 1 } } },
			{ $sort: { count: -1 } },
		]);
		return res.json({
			totalProducts,
			inStockProducts,
			outOfStockProducts,
			categoryStats,
		});
	} catch (err) {
		console.error('Product stats error:', err);
		return res.status(500).json({ error: 'Failed to fetch product statistics' });
	}
});

module.exports = router;