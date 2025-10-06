const express = require('express');
const router = express.Router();
const { body, validationResult } = require('express-validator');
const Order = require('../models/Order');
const User = require('../models/User');
const nodemailer = require('nodemailer');

// Helper for email
function createTransport() {
	if (process.env.SMTP_HOST) {
		return nodemailer.createTransport({
			host: process.env.SMTP_HOST,
			port: Number(process.env.SMTP_PORT || 587),
			secure: process.env.SMTP_SECURE === 'true',
			auth: {
				user: process.env.SMTP_USER,
				pass: process.env.SMTP_PASS,
			},
		});
	}
	return nodemailer.createTransport({
		service: 'gmail',
		auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_PASS },
	});
}

// GET /orders (admin)
router.get('/', async (req, res) => {
	   try {
		   const page = parseInt(req.query.page) > 0 ? parseInt(req.query.page) : 1;
		   const limit = parseInt(req.query.limit) > 0 ? parseInt(req.query.limit) : 10;
		   const skip = (page - 1) * limit;
		   const [orders, total] = await Promise.all([
			   Order.find().sort({ createdAt: -1 }).skip(skip).limit(limit),
			   Order.countDocuments()
		   ]);
		   return res.json({
			   orders,
			   pagination: {
				   page,
				   limit,
				   total,
				   pages: Math.ceil(total / limit),
				   hasNext: page * limit < total,
				   hasPrev: page > 1
			   }
		   });
	   } catch (err) {
		   console.error('Get orders error:', err);
		   return res.status(500).json({ error: 'Failed to get orders' });
	   }
});

// POST /orders (place new order)
router.post(
	'/',
	[
		body('userEmail').isEmail().withMessage('Valid user email required'),
		body('address.name').notEmpty().withMessage('Name required'),
		body('address.email').isEmail().withMessage('Valid email required'),
		body('address.phone').isLength({ min: 8 }).withMessage('Phone required'),
		body('address.doorNo').notEmpty().withMessage('Door No required'),
		body('address.landmark').notEmpty().withMessage('Landmark required'),
		body('address.pincode').isLength({ min: 4 }).withMessage('Pincode required'),
		body('address.addressLine').notEmpty().withMessage('Address required'),
		body('address.city').notEmpty().withMessage('City required'),
		body('address.state').notEmpty().withMessage('State required'),
		body('address.country').notEmpty().withMessage('Country required'),
		body('payment.method').notEmpty().withMessage('Payment method required'),
		body('items').isArray({ min: 1 }).withMessage('At least one item required'),
		body('total').isNumeric().withMessage('Total required'),
	],
	async (req, res) => {
		const errors = validationResult(req);
		if (!errors.isEmpty()) {
			return res.status(400).json({ errors: errors.array() });
		}
		try {
			const { userEmail, address, payment, items, total } = req.body;
			// Find user
			const user = await User.findOne({ email: userEmail });
			if (!user) return res.status(404).json({ error: 'User not found' });

						// Create order document in Order collection
			const orderDoc = await Order.create({
								userEmail,
								address: {
									name: address.name,
									email: address.email,
									phone: address.phone,
									doorNo: address.doorNo,
									landmark: address.landmark,
									pincode: address.pincode,
									addressLine: address.addressLine,
									city: address.city,
									state: address.state,
									country: address.country
								},
								payment,
								items,
				total,
				createdAt: new Date(),
				deliveryStatus: 'Order Placed',
				deliveryTimestamps: { placedAt: new Date() },
						});


			// Store order ObjectId in user's orders array
						user.orders.push(orderDoc._id);
						try {
							await user.save();

						} catch (userSaveErr) {
							console.error('[ORDER PLACED] Failed to save user orders array:', userSaveErr);
							return res.status(500).json({ error: 'Order placed but failed to update user orders. Please contact support.' });
						}
						user.cart = [];
						await user.save();

			// Send confirmation email
						try {
								const transporter = createTransport();
								const fromAddr = process.env.MAIL_FROM || process.env.SMTP_USER || process.env.GMAIL_USER;
								const to = address.email || userEmail;

								// Build items rows
												const itemRows = items
													.map((item) => {
														const qty = Number(item.quantity) || 0;
														const price = Number(item.price) || 0;
														const subtotal = price * qty;
														return `
															<tr>
																<td style="padding:8px 12px;border-bottom:1px solid #eee;color:#333;">${item.name}</td>
																<td style="padding:8px 12px;border-bottom:1px solid #eee;color:#555;text-align:center;">${qty}</td>
																<td style="padding:8px 12px;border-bottom:1px solid #eee;color:#555;text-align:right;">₹${price}</td>
																<td style="padding:8px 12px;border-bottom:1px solid #eee;color:#111;font-weight:600;text-align:right;">₹${subtotal}</td>
															</tr>`;
													})
									.join('');

								const orderDate = new Date(orderDoc.createdAt || Date.now()).toLocaleString('en-IN');
								const paymentText = payment && payment.method === 'card' ? 'Card (Paid)' : 'Cash on Delivery';

								const html = `
<!doctype html>
<html>
	<head>
		<meta name="viewport" content="width=device-width" />
		<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
		<title>Order Confirmation - RS Collections</title>
	</head>
	<body style="margin:0;padding:0;background:#f6f8fb;font-family:Arial,Helvetica,sans-serif;color:#333;">
		<table role="presentation" cellspacing="0" cellpadding="0" border="0" style="width:100%;background:#f6f8fb;padding:24px 0;">
			<tr>
				<td align="center">
					<table role="presentation" cellspacing="0" cellpadding="0" border="0" style="width:100%;max-width:640px;background:#ffffff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,0.06);">
						<tr>
							<td style="background:#111827;padding:20px 24px;color:#ffffff;">
								<div style="font-size:20px;font-weight:700;">RS Collections</div>
							</td>
						</tr>
						<tr>
							<td style="padding:24px;">
								<h2 style="margin:0 0 8px 0;font-size:22px;color:#111827;">Thanks for ordering from RS Collections</h2>
								<p style="margin:0 0 16px 0;color:#374151;">Here are your order details:</p>

								<div style="background:#f9fafb;border:1px solid #e5e7eb;border-radius:6px;padding:12px 16px;margin-bottom:16px;">
									<div style="font-size:14px;color:#6b7280;">Order ID</div>
									<div style="font-size:14px;color:#111827;font-weight:600;">#${String(orderDoc._id)}</div>
									<div style="height:8px;"></div>
									<div style="font-size:14px;color:#6b7280;">Order Date</div>
									<div style="font-size:14px;color:#111827;">${orderDate}</div>
								</div>

								<h3 style="margin:0 0 8px 0;font-size:16px;color:#111827;">Order Summary</h3>
												<table role="presentation" cellspacing="0" cellpadding="0" border="0" style="width:100%;border-collapse:collapse;margin-bottom:12px;">
									<thead>
										<tr>
											<th align="left" style="padding:8px 12px;border-bottom:2px solid #e5e7eb;color:#374151;font-size:13px;text-transform:uppercase;">Item</th>
															<th align="center" style="padding:8px 12px;border-bottom:2px solid #e5e7eb;color:#374151;font-size:13px;text-transform:uppercase;">Qty</th>
											<th align="right" style="padding:8px 12px;border-bottom:2px solid #e5e7eb;color:#374151;font-size:13px;text-transform:uppercase;">Price</th>
											<th align="right" style="padding:8px 12px;border-bottom:2px solid #e5e7eb;color:#374151;font-size:13px;text-transform:uppercase;">Subtotal</th>
										</tr>
									</thead>
									<tbody>
										${itemRows}
									</tbody>
								</table>

								<table role="presentation" cellspacing="0" cellpadding="0" border="0" style="width:100%;margin:8px 0 20px;">
									<tr>
										<td style="padding:4px 12px;color:#374151;">Payment Method</td>
										<td align="right" style="padding:4px 12px;color:#111827;font-weight:600;">${paymentText}</td>
									</tr>
									<tr>
										<td style="padding:4px 12px;color:#374151;">Order Total</td>
										<td align="right" style="padding:4px 12px;color:#111827;font-weight:700;">₹${total}</td>
									</tr>
								</table>

								<h3 style="margin:0 0 8px 0;font-size:16px;color:#111827;">Shipping Address</h3>
								<div style="border:1px solid #e5e7eb;border-radius:6px;padding:12px 16px;color:#111827;margin-bottom:16px;">
									<div>${address.name}</div>
									<div>${address.doorNo ? address.doorNo + ', ' : ''}${address.addressLine}</div>
									<div>${address.landmark ? address.landmark + ', ' : ''}${address.city}, ${address.state}, ${address.country} - ${address.pincode}</div>
									<div>Phone: ${address.phone}</div>
								</div>

								<p style="margin:0;color:#374151;">Thank you again for shopping with RS Collections. We’ll start processing your order shortly. If you have any questions, simply reply to this email.</p>
							</td>
						</tr>
						<tr>
							<td style="background:#f3f4f6;padding:16px;text-align:center;color:#6b7280;font-size:12px;">
								© ${new Date().getFullYear()} RS Collections. All rights reserved.
							</td>
						</tr>
					</table>
				</td>
			</tr>
		</table>
	</body>
 </html>`;

								await transporter.sendMail({
									from: `RS Collections <${fromAddr}>`,
										to,
										subject: 'Order Confirmation - RS Collections',
										html,
								});
						} catch (mailErr) {
				console.error('Order confirmation email error:', mailErr);
				// Don't fail the order if email fails
			}

			return res.status(201).json({ message: 'Order placed', order: orderDoc });
		} catch (err) {
			console.error('Order placement error:', err);
			return res.status(500).json({ error: 'Failed to place order', details: err.message });
		}
	}
);

module.exports = router;