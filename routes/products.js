const express = require('express');
const router = express.Router();
const Product = require('../models/Product');
const Order = require('../models/Order');

// GET /products (list, with optional filters)
router.get('/', async (req, res) => {
	try {
		const { category, subCategory, productId, page = 1, limit = 50 } = req.query;
		let query = { inStock: true };
		if (productId) {
			query = { productId };
		} else {
			if (category && category !== 'all') {
			query.category = category;
			}
			if (subCategory && subCategory !== 'all') {
				query.subCategory = subCategory;
			}
		}
		const products = await Product.find(query)
			.sort({ createdAt: -1 })
			.limit(limit * 1)
			.skip((page - 1) * limit)
			.select('productId name images price category subCategory description inStock createdAt');
		const total = await Product.countDocuments(query);
		return res.json({
			products,
			pagination: {
				current: parseInt(page),
				pages: Math.ceil(total / limit),
				total,
				hasNext: page * limit < total,
				hasPrev: page > 1,
			},
		});
	} catch (err) {
		console.error('Get public products error:', err);
		return res.status(500).json({ error: 'Failed to fetch products' });
	}
});

// GET /products/best-sellers (most ordered products)
router.get('/best-sellers', async (req, res) => {
	try {
		const limit = Math.min(parseInt(req.query.limit) || 20, 50);
		// Aggregate orders to sum quantities per product id
			const pipeline = [
			{ $unwind: '$items' },
			{ $group: {
					_id: '$items.id',
					totalQuantity: { $sum: { $ifNull: ['$items.quantity', 1] } },
					orderCount: { $sum: 1 }
			}},
				// Sort by number of orders first, then total quantity as tiebreaker
				{ $sort: { orderCount: -1, totalQuantity: -1 } },
			{ $limit: limit }
		];
		const agg = await Order.aggregate(pipeline);
		const ids = agg.map(a => a._id).filter(Boolean);
		// Fetch product details for those ids (match by productId or _id)
		const products = await Product.find({
			$or: [
				{ productId: { $in: ids } },
				{ _id: { $in: ids.filter(v => /^[a-fA-F0-9]{24}$/.test(String(v))) } }
			]
		}).select('productId name images price category subCategory description inStock createdAt');

		// Map results preserving order by agg
		const productMap = new Map();
		for (const p of products) {
			productMap.set(String(p.productId), p);
			productMap.set(String(p._id), p);
		}
			const result = agg
				.map(a => {
					const p = productMap.get(String(a._id));
					if (!p) return null;
					return {
						product: p,
						metrics: { totalQuantity: a.totalQuantity, orderCount: a.orderCount }
					};
				})
				.filter(Boolean);

			// Deduplicate products that may appear due to mixed id usage (productId vs _id)
			const merged = new Map();
			for (const r of result) {
				const key = String(r.product?._id || r.product?.productId);
				if (!key) continue;
				if (!merged.has(key)) {
					merged.set(key, r);
				} else {
					const existing = merged.get(key);
					existing.metrics.totalQuantity += r.metrics.totalQuantity;
					existing.metrics.orderCount += r.metrics.orderCount;
				}
			}
				const out = Array.from(merged.values()).sort((a, b) => {
					if ((b.metrics?.orderCount || 0) !== (a.metrics?.orderCount || 0)) {
						return (b.metrics?.orderCount || 0) - (a.metrics?.orderCount || 0);
					}
					return (b.metrics?.totalQuantity || 0) - (a.metrics?.totalQuantity || 0);
				});

			return res.json({ bestSellers: out });
	} catch (err) {
		console.error('Best sellers error:', err);
		return res.status(500).json({ error: 'Failed to fetch best sellers' });
	}
});

// GET /products/best-sellers-by-category?limit=10
// Returns top N products with most orders for each category
router.get('/best-sellers-by-category', async (req, res) => {
	try {
		const limit = Math.min(parseInt(req.query.limit) || 10, 50);

		// Aggregate order metrics per product id
		const pipeline = [
			{ $unwind: '$items' },
					{
						$group: {
							_id: '$items.id',
							totalQuantity: { $sum: { $ifNull: ['$items.quantity', 1] } },
							orderCount: { $sum: 1 },
						},
					},
					// Ensure we have a string form of the id for lookups
					{ $addFields: { itemIdStr: { $toString: '$_id' } } },
			// Sort globally first; we'll preserve order inside categories
			{ $sort: { orderCount: -1, totalQuantity: -1 } },
					// Lookup product by either productId or _id (convert string to ObjectId when possible)
							{
								$lookup: {
									from: 'products',
									let: { itemIdStr: '$itemIdStr' },
									pipeline: [
										{
											$match: {
												$expr: {
													$or: [
														{ $eq: ['$productId', '$$itemIdStr'] },
														{ $eq: [ { $toString: '$_id' }, '$$itemIdStr' ] }
													]
												}
											}
										},
										{ $project: { productId:1, name:1, images:1, price:1, category:1, subCategory:1, description:1, inStock:1, createdAt:1 } }
									],
									as: 'productDoc'
								}
							},
					{ $addFields: { product: { $arrayElemAt: ['$productDoc', 0] } } },
					{ $match: { product: { $type: 'object' } } },
					{
						$addFields: {
							category: {
								$replaceAll: {
									input: {
										$trim: {
											input: {
												$toLower: { $ifNull: ['$product.category', 'uncategorized'] }
											}
										}
									},
									find: ' ',
									replacement: '-',
								},
							},
						},
					},
			{
				$group: {
					_id: '$category',
					items: {
						$push: {
							product: '$product',
							metrics: { orderCount: '$orderCount', totalQuantity: '$totalQuantity' },
						},
					},
				},
			},
			{
				$project: {
					_id: 0,
					category: '$_id',
					top: { $slice: ['$items', limit] },
				},
			},
		];

		const agg = await Order.aggregate(pipeline);

		// Convert to key-value map by category
		const byCategory = {};
		for (const entry of agg) {
			byCategory[entry.category] = entry.top;
		}

		return res.json({ byCategory });
	} catch (err) {
		console.error('Best sellers by category error:', err);
		return res.status(500).json({ error: 'Failed to fetch best sellers by category' });
	}
});

// GET /products/popular-weekly-by-category?limit=10&start=ISO_DATE&end=ISO_DATE
// Returns top N products with most orders for each category within the given week/date range
router.get('/popular-weekly-by-category', async (req, res) => {
	try {
		const limit = Math.min(parseInt(req.query.limit) || 10, 50);
		const now = new Date();
		const providedStart = req.query.start ? new Date(req.query.start) : null;
		const providedEnd = req.query.end ? new Date(req.query.end) : null;
		// Default to rolling last 7 days if dates not provided
		const defaultStart = new Date(now);
		defaultStart.setDate(defaultStart.getDate() - 7);
		defaultStart.setHours(0, 0, 0, 0);
		const start = providedStart && !isNaN(providedStart) ? providedStart : defaultStart;
		const end = providedEnd && !isNaN(providedEnd) ? providedEnd : now;

		const pipeline = [
			{ $match: { createdAt: { $gte: start, $lte: end } } },
			{ $unwind: '$items' },
					{
						$group: {
							_id: '$items.id',
							totalQuantity: { $sum: { $ifNull: ['$items.quantity', 1] } },
							orderCount: { $sum: 1 },
						},
					},
					{ $addFields: { itemIdStr: { $toString: '$_id' } } },
			{ $sort: { orderCount: -1, totalQuantity: -1 } },
					// Lookup product by either productId or _id (convert string to ObjectId when possible)
							{
								$lookup: {
									from: 'products',
									let: { itemIdStr: '$itemIdStr' },
									pipeline: [
										{
											$match: {
												$expr: {
													$or: [
														{ $eq: ['$productId', '$$itemIdStr'] },
														{ $eq: [ { $toString: '$_id' }, '$$itemIdStr' ] }
													]
												}
											}
										},
										{ $project: { productId:1, name:1, images:1, price:1, category:1, subCategory:1, description:1, inStock:1, createdAt:1 } }
									],
									as: 'productDoc'
								}
							},
					{ $addFields: { product: { $arrayElemAt: ['$productDoc', 0] } } },
			{ $match: { product: { $type: 'object' } } },
					{
						$addFields: {
							category: {
								$replaceAll: {
									input: {
										$trim: {
											input: {
												$toLower: { $ifNull: ['$product.category', 'uncategorized'] }
											}
										}
									},
									find: ' ',
									replacement: '-',
								},
							},
						},
					},
			{
				$group: {
					_id: '$category',
					items: {
						$push: {
							product: '$product',
							metrics: { orderCount: '$orderCount', totalQuantity: '$totalQuantity' },
						},
					},
				},
			},
			{
				$project: {
					_id: 0,
					category: '$_id',
					top: { $slice: ['$items', limit] },
				},
			},
		];

			const agg = await Order.aggregate(pipeline);
			const byCategory = {};
			for (const entry of agg) {
				const key = String(entry.category || '')
					.toLowerCase()
					.trim()
					.replace(/\s+/g, '-');
				byCategory[key || 'uncategorized'] = entry.top || [];
			}
		return res.json({ byCategory, range: { start, end } });
	} catch (err) {
		console.error('Popular weekly by category error:', err);
		return res.status(500).json({ error: 'Failed to fetch weekly popular products by category' });
	}
});

// GET /products/:productId (single product)
router.get('/:productId', async (req, res) => {
	try {
		const { productId } = req.params;
		const product = await Product.findOne({ productId })
			.select('productId name images price category subCategory description inStock createdAt');
		if (!product) {
			return res.status(404).json({ error: 'Product not found' });
		}
		return res.json({ product });
	} catch (err) {
		console.error('Get single product error:', err);
		return res.status(500).json({ error: 'Failed to fetch product' });
	}
});

module.exports = router;