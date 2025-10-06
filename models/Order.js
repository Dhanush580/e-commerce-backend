// backend/models/Order.js
const mongoose = require('mongoose');

const orderSchema = new mongoose.Schema({
  userEmail: { type: String, required: true },
  address: {
    name: String,
    email: String,
    phone: String,
    doorNo: String,
    landmark: String,
    pincode: String,
    addressLine: String,
    city: String,
    state: String,
    country: String
  },
  payment: {
    method: { type: String, enum: ['card', 'cod'], required: true },
    status: { type: String, enum: ['pending', 'paid', 'failed'], default: 'pending' },
    razorpayPaymentId: String
  },
  items: [
    {
      id: String,
      name: String,
      price: Number,
      image: String,
      selectedSize: String,
      quantity: Number
    }
  ],
  deliveryStatus: {
    type: String,
    enum: ['Order Placed', 'Out for Delivery', 'Delivered'],
    default: 'Order Placed'
  },
  deliveryTimestamps: {
    placedAt: { type: Date },
    outForDeliveryAt: { type: Date },
    deliveredAt: { type: Date },
  },
  total: Number,
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Order', orderSchema);
