// ...existing code...


require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { createImageRouter } = require('./utils/gridfs');

const authenticateAdmin = require('./middlewares/authenticateAdmin');
const Order = require('./models/Order');
const Product = require('./models/Product');
const User = require('./models/User');
const Admin = require('./models/Admin');


const app = express();
// Trust Render/Vercel proxies so secure cookies work behind HTTPS proxies
app.set('trust proxy', 1);

// ---- MongoDB connection event logs ----
const dbConn = mongoose.connection;
dbConn.on('connected', () => {
	const { host, name } = mongoose.connection;
	console.log(`[DB] Connected to MongoDB: ${host}/${name}`);
});
dbConn.on('error', (err) => {
	console.error('[DB] MongoDB connection error:', err.message || err);
});
dbConn.on('disconnected', () => {
	console.warn('[DB] MongoDB disconnected');
});

// Logout route (must be after app is defined)
const logoutRouter = require('./routes/logout');
app.use('/auth/logout', logoutRouter);
// User orders route
const userOrdersRouter = require('./userOrders');
app.use('/user-orders', userOrdersRouter);
// Middleware: CORS and JSON body parser (must be before all routes)
function originMatches(origin, patterns) {
	return patterns.some((p) => {
		if (!p) return false;
		if (p === '*') return true;
		if (p.includes('*')) {
			// Convert wildcard pattern to regex: escape regex chars then turn '*' into '.*'
			const escaped = p.replace(/[-\/\\^$+?.()|[\]{}]/g, '\\$&');
			const patternRegex = '^' + escaped.replace(/\*/g, '.*') + '$';
			const regex = new RegExp(patternRegex);
			return regex.test(origin);
		}
		return origin === p;
	});
}

app.use(cors({
	origin: (origin, cb) => {
		const allowedPatterns = (process.env.FRONTEND_ORIGIN || 'http://localhost:5173')
			.split(',')
			.map((s) => s.trim())
			.filter(Boolean);
		// Allow non-browser tools with no origin
		if (!origin) return cb(null, true);
		if (originMatches(origin, allowedPatterns)) return cb(null, true);
		console.warn(`[CORS] Blocked origin: ${origin}. Allowed: ${allowedPatterns.join(', ')}`);
		return cb(null, false);
	},
	credentials: true,
}));

// Ensure only a single Access-Control-Allow-Origin header is present and set Vary: Origin
app.use((req, res, next) => {
	const reqOrigin = req.headers.origin;
	const current = res.getHeader('Access-Control-Allow-Origin');
	if (reqOrigin && current) {
		// Override any comma-separated or duplicate header with the actual request origin
		res.setHeader('Access-Control-Allow-Origin', reqOrigin);
	}
	// Help caches serve the right variant per Origin
	const vary = res.getHeader('Vary');
	if (!vary) {
		res.setHeader('Vary', 'Origin');
	} else if (!String(vary).includes('Origin')) {
		res.setHeader('Vary', String(vary) + ', Origin');
	}
	next();
});

// Health check for Render
app.get('/', (req, res) => res.send('OK'));

app.use(express.json());
app.use(cookieParser());

// Image serving routes
// 1) New: Serve images from MongoDB GridFS under /images/:id
app.use('/images', createImageRouter());

// 2) Back-compat: if products still reference /uploads/xyz, serve those files if present.
//    Also, if file not found locally, attempt to parse filename as GridFS id and proxy.
app.use('/uploads', async (req, res, next) => {
	const localPath = path.join(__dirname, 'uploads', req.path.replace(/^\//, ''));
	fs.stat(localPath, (err, stat) => {
		if (!err && stat && stat.isFile()) {
			return express.static(path.join(__dirname, 'uploads'))(req, res, next);
		}
		// If not found locally, try as GridFS id shim: /uploads/<gridfsId>
		const maybeId = req.path.replace(/^\//, '').split('.')[0];
		if (/^[a-f\d]{24}$/i.test(maybeId)) {
			return res.redirect(302, `/images/${maybeId}`);
		}
		return next();
	});
});

// Orders routes moved to routes/orders.js
const ordersRouter = require('./routes/orders');
app.use('/orders', ordersRouter);

// Wishlist routes moved to routes/wishlist.js
const wishlistRouter = require('./routes/wishlist');
app.use('/wishlist', wishlistRouter);

const PORT = process.env.PORT || 5000;


// Mount admin router for all /admin endpoints (products, stats, image upload, etc)
const adminRouter = require('./routes/admin');
app.use('/admin', adminRouter);


// Auth routes (must be after app is defined)
const authRouter = require('./routes/auth');
app.use('/auth', authRouter);

// Admin login endpoint (password-based for admins)
app.post('/auth/admin-login', async (req, res) => {
	try {
		const { email, password } = req.body || {};
		

		
		if (!email || !password) {

			return res.status(400).json({ error: 'Email and password are required' });
		}

		// Find admin by email in Admin collection
		const admin = await Admin.findOne({ email: email.toLowerCase() });
        
        
		if (admin) {
			// admin found
		}
        
		if (!admin) {

			return res.status(401).json({ error: 'Invalid admin credentials' });
		}

		// Check password (comparing with stored hashed password)
		const bcrypt = require('bcryptjs');

        
		const isPasswordValid = await bcrypt.compare(password, admin.password);

        
		if (!isPasswordValid) {

			return res.status(401).json({ error: 'Invalid admin credentials' });
		}

		// Create or find corresponding user record with admin role
		let user = await User.findOne({ email: email.toLowerCase() });

        
		if (!user) {

			user = await User.create({ email: email.toLowerCase(), role: 'admin' });
		} else if (user.role !== 'admin') {

			user.role = 'admin';
			await user.save();
		}

		// Generate JWT token
		const token = jwt.sign({ sub: user._id, email: user.email }, process.env.JWT_SECRET || 'dev_secret', { expiresIn: '7d' });
		// Align with middleware which reads 'admin_auth' cookie
		res.cookie('admin_auth', token, {
			httpOnly: true,
			sameSite: process.env.COOKIE_SAMESITE || 'lax',
			secure: process.env.COOKIE_SECURE === 'true',
			maxAge: 7 * 24 * 60 * 60 * 1000,
		});


	return res.json({ message: 'Admin login successful', user: { id: user._id, email: user.email, role: user.role } });
	} catch (err) {
		console.error('admin login error', err);
		return res.status(500).json({ error: 'Login failed' });
	}
});

// Admin registration endpoint
app.post('/auth/admin-register', async (req, res) => {
	try {
		const { email, password } = req.body || {};
		

		
		if (!email || !password) {
			return res.status(400).json({ error: 'Email and password are required' });
		}

		// Check if admin already exists
		const existingAdmin = await Admin.findOne({ email: email.toLowerCase() });
		if (existingAdmin) {
			return res.status(400).json({ error: 'Admin already exists with this email' });
		}

		// Hash password
		const bcrypt = require('bcryptjs');
		const hashedPassword = await bcrypt.hash(password, 10);


		// Create admin record
		const admin = await Admin.create({
			email: email.toLowerCase(),
			password: hashedPassword
		});


		// Create or update user record with admin role
		let user = await User.findOne({ email: email.toLowerCase() });
		if (!user) {
			user = await User.create({ email: email.toLowerCase(), role: 'admin' });

		} else {
			user.role = 'admin';
			await user.save();

		}


		return res.json({ 
			message: 'Admin registered successfully', 
			admin: { 
				   id: admin._id, 
				   email: admin.email 
			   },
			   user: {
				   id: user._id,
				   email: user.email,
				   role: user.role
			   }
		   });
	} catch (err) {
		console.error('admin registration error', err);
		return res.status(500).json({ error: 'Registration failed: ' + err.message });
	}
});

// Debug endpoint to check admin existence
app.get('/debug/admin-check/:email', async (req, res) => {
	try {
		const { email } = req.params;
		const admin = await Admin.findOne({ email });
		const user = await User.findOne({ email });
		
		res.json({
			email,
			adminExists: !!admin,
			adminData: admin ? { email: admin.email, createdAt: admin.createdAt } : null,
			userExists: !!user,
			userData: user ? { email: user.email, role: user.role, createdAt: user.createdAt } : null
		});
	} catch (err) {
		res.status(500).json({ error: err.message });
	}
});

// --------- PRODUCT MANAGEMENT APIs (Admin Only) ---------

// Product routes moved to routes/products.js
const productsRouter = require('./routes/products');
app.use('/products', productsRouter);


// Add new product (Admin only)
app.post('/admin/products', authenticateAdmin, async (req, res) => {
	try {
		const { productId, name, images, price, category, description, inStock } = req.body || {};
		

		
		if (!productId || !name || !images || !Array.isArray(images) || images.length === 0 || !price || !category || !description) {
			return res.status(400).json({ errors: [{ msg: 'All required fields must be provided, images must be a non-empty array' }] });
		}

		// Check if product ID already exists
		const existingProduct = await Product.findOne({ productId });
		if (existingProduct) {
			return res.status(400).json({ error: 'Product ID already exists' });
		}

		// Create new product
		const product = await Product.create({
			productId,
			name,
			images, // Now handling array of images
			price: parseFloat(price),
			category,
			description,
			inStock: inStock !== undefined ? inStock : true,
			updatedAt: new Date()
		});


		return res.json({ message: 'Product added successfully', product });
	} catch (err) {
		console.error('Add product error:', err);
		return res.status(500).json({ error: 'Failed to add product: ' + err.message });
	}
});

// Get all products (Admin only)
app.get('/admin/products', authenticateAdmin, async (req, res) => {
	try {
		const { page = 1, limit = 20, category, search } = req.query;
		
		let query = {};
		if (category && category !== 'all') {
			query.category = category;
		}
		if (search) {
			query.$or = [
				{ name: { $regex: search, $options: 'i' } },
				{ productId: { $regex: search, $options: 'i' } },
				{ description: { $regex: search, $options: 'i' } }
			];
		}

		const products = await Product.find(query)
			.sort({ createdAt: -1 })
			.limit(limit * 1)
			.skip((page - 1) * limit);

		const total = await Product.countDocuments(query);

		return res.json({
			products,
			pagination: {
				current: parseInt(page),
				pages: Math.ceil(total / limit),
				total,
				hasNext: page * limit < total,
				hasPrev: page > 1
			}
		});
	} catch (err) {
		console.error('Get products error:', err);
		return res.status(500).json({ error: 'Failed to fetch products' });
	}
});




// Cart routes moved to routes/cart.js
const cartRouter = require('./routes/cart');
app.use('/cart', cartRouter);

// --------- Admin Routes ---------
// Get admin dashboard analytics
app.get('/admin/dashboard', authenticateAdmin, async (req, res) => {
	try {
		const totalUsers = await User.countDocuments();
		// Count wishlist, cart, and orders from user documents
		const users = await User.find({}, 'wishlist cart orders');
		let totalWishlistItems = 0;
		let totalCartItems = 0;
		let totalOrders = 0;
		let totalRevenue = 0;
		const wishlistMap = new Map();
		const cartMap = new Map();
		let allOrderIds = [];
		for (const user of users) {
			totalWishlistItems += (user.wishlist || []).length;
			totalCartItems += (user.cart || []).reduce((sum, item) => sum + (item.quantity || 1), 0);
			totalOrders += (user.orders || []).length;
			   allOrderIds = allOrderIds.concat(user.orders || []);
			for (const item of user.wishlist || []) {
				if (item && item.id) {
					wishlistMap.set(item.id, (wishlistMap.get(item.id) || { count: 0, product: item }));
					wishlistMap.get(item.id).count += 1;
				}
			}
			for (const item of user.cart || []) {
				if (item && item.id) {
					cartMap.set(item.id, (cartMap.get(item.id) || { totalQuantity: 0, product: item }));
					cartMap.get(item.id).totalQuantity += (item.quantity || 1);
				}
			}
		}
			   // Filter only valid ObjectIds (string of 24 hex chars or actual ObjectId)
			   const validOrderIds = allOrderIds.filter(id => {
				   if (!id) return false;
				   if (typeof id === 'string' && /^[a-fA-F0-9]{24}$/.test(id)) return true;
				   if (typeof id === 'object' && id._bsontype === 'ObjectID') return true;
				   return false;
			   });
			   const allOrders = await Order.find({ _id: { $in: validOrderIds } });
		for (const order of allOrders) {
			if (order && order.payment && ['paid', 'pending'].includes(order.payment.status)) {
				totalRevenue += order.total || 0;
			}
		}
		// Get recent user registrations (last 30 days)
		const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
		const recentUsers = await User.countDocuments({ createdAt: { $gte: thirtyDaysAgo } });

		// Top wishlist items
		const topWishlistItems = Array.from(wishlistMap.values())
			.sort((a, b) => b.count - a.count)
			.slice(0, 5)
			.map(entry => ({ ...entry.product, count: entry.count }));

		// Top cart items
		const topCartItems = Array.from(cartMap.values())
			.sort((a, b) => b.totalQuantity - a.totalQuantity)
			.slice(0, 5)
			.map(entry => ({ ...entry.product, totalQuantity: entry.totalQuantity }));

		return res.json({
			analytics: {
				totalUsers,
				totalWishlistItems,
				totalCartItems,
				recentUsers,
				topWishlistItems,
				topCartItems,
				totalOrders,
				totalRevenue
			}
		});
	} catch (err) {
		console.error('Admin dashboard error:', err);
		return res.status(500).json({ error: 'Failed to get dashboard data' });
	}
});

// Get all users
app.get('/admin/users', authenticateAdmin, async (req, res) => {
	try {
		const page = parseInt(req.query.page) || 1;
		const limit = parseInt(req.query.limit) || 20;
		const skip = (page - 1) * limit;

		const users = await User.find({})
			.select('email role createdAt')
			.sort({ createdAt: -1 })
			.skip(skip)
			.limit(limit);

		const totalUsers = await User.countDocuments();

		return res.json({
			users,
			pagination: {
				currentPage: page,
				totalPages: Math.ceil(totalUsers / limit),
				totalUsers,
				hasNextPage: page < Math.ceil(totalUsers / limit),
				hasPrevPage: page > 1
			}
		});
	} catch (err) {
		console.error('Get users error:', err);
		return res.status(500).json({ error: 'Failed to get users' });
	}
});

// Update user role
app.put('/admin/users/:email/role', authenticateAdmin, async (req, res) => {
	try {
		const { email } = req.params;
		const { role } = req.body;

		if (!['user', 'admin'].includes(role)) {
			return res.status(400).json({ error: 'Invalid role' });
		}

		const user = await User.findOneAndUpdate(
			{ email },
			{ role },
			{ new: true }
		);

		if (!user) {
			return res.status(404).json({ error: 'User not found' });
		}

		return res.json({ message: 'User role updated', user: { email: user.email, role: user.role } });
	} catch (err) {
		console.error('Update user role error:', err);
		return res.status(500).json({ error: 'Failed to update user role' });
	}
});

// Get user's wishlist and cart details
app.get('/admin/users/:email/details', authenticateAdmin, async (req, res) => {
	try {
		const { email } = req.params;

		const user = await User.findOne({ email }).select('email role createdAt');
		if (!user) {
			return res.status(404).json({ error: 'User not found' });
		}

		const wishlistItems = await Wishlist.find({ email }).sort({ addedAt: -1 });
		const cartItems = await Cart.find({ email }).sort({ addedAt: -1 });

		return res.json({
			user,
			wishlist: wishlistItems.map(item => item.productData),
			cart: cartItems.map(item => ({ ...item.productData, quantity: item.quantity }))
		});
	} catch (err) {
		console.error('Get user details error:', err);
		return res.status(500).json({ error: 'Failed to get user details' });
	}
});

// Delete user (admin only)
app.delete('/admin/users/:email', authenticateAdmin, async (req, res) => {
	try {
		const { email } = req.params;

		// Don't allow deleting yourself
		if (email === req.user.email) {
			return res.status(400).json({ error: 'Cannot delete your own account' });
		}

		// Delete user and associated data
		await User.deleteOne({ email });
		await Wishlist.deleteMany({ email });
		await Cart.deleteMany({ email });

		return res.json({ message: 'User deleted successfully' });
	} catch (err) {
		console.error('Delete user error:', err);
		return res.status(500).json({ error: 'Failed to delete user' });
	}
});

// Example protected route
app.get('/me', (req, res) => {
	try {
		const token = req.cookies.auth;
		if (!token) return res.status(401).json({ error: 'Unauthorized' });
		const payload = jwt.verify(token, process.env.JWT_SECRET || 'dev_secret');
		return res.json({ user: { id: payload.sub, email: payload.email } });
	} catch (err) {
		return res.status(401).json({ error: 'Unauthorized' });
	}
});
// Admin: Update delivery status of an order
app.patch('/orders/:orderId/delivery-status', async (req, res) => {
	try {
		const { orderId } = req.params;
		const { deliveryStatus } = req.body;
		const validStatuses = ['Order Placed', 'Out for Delivery', 'Delivered'];
		if (!validStatuses.includes(deliveryStatus)) {
			return res.status(400).json({ error: 'Invalid delivery status' });
		}
			const now = new Date();
			const update = { deliveryStatus };
			if (deliveryStatus === 'Order Placed') {
				update['deliveryTimestamps.placedAt'] = now;
			} else if (deliveryStatus === 'Out for Delivery') {
				update['deliveryTimestamps.outForDeliveryAt'] = now;
			} else if (deliveryStatus === 'Delivered') {
				update['deliveryTimestamps.deliveredAt'] = now;
			}
			const order = await Order.findByIdAndUpdate(orderId, update, { new: true });
		if (!order) return res.status(404).json({ error: 'Order not found' });
		return res.json({ message: 'Delivery status updated', order });
	} catch (err) {
		console.error('Update delivery status error:', err);
		return res.status(500).json({ error: 'Failed to update delivery status' });
	}
});


// Profile routes moved to routes/profile.js
const profileRouter = require('./routes/profile');
app.use('/profile', profileRouter);

// --------- DB connect and start ---------
async function start() {
	const mongoUri = process.env.MONGODB_URI;
	if (!mongoUri) {
		console.error('Missing MONGODB_URI in environment');
		process.exit(1);
	}
	await mongoose.connect(mongoUri);
	// Extra safety log in case the 'connected' event fires before this
	if (mongoose.connection.readyState === 1) {
		const { host, name } = mongoose.connection;
		console.log(`[DB] Connection established: ${host}/${name}`);
	}
	app.listen(PORT, () => {
		const env = process.env.NODE_ENV || 'development';
		const origin = process.env.FRONTEND_ORIGIN || 'http://localhost:5173';
		console.log(`[API] Server listening on http://localhost:${PORT} (env=${env})`);
		console.log(`[CORS] Allowed origin: ${origin}`);
	});
}

start().catch((e) => {
	console.error('Startup error', e);
	process.exit(1);
});

