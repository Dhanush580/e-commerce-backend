const mongoose = require('mongoose');

const addressSchema = new mongoose.Schema({
  doorNo: { type: String },
  landmark: { type: String },
  addressLine1: { type: String, required: true },
  addressLine2: { type: String },
  city: { type: String, required: true },
  state: { type: String, required: true },
  pincode: { type: String, required: true },
  country: { type: String, required: true },
}, { _id: false });

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  name: { type: String },
  mobile: { type: String },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  wishlist: [{ type: mongoose.Schema.Types.Mixed }],
  cart: [{ type: mongoose.Schema.Types.Mixed }],
  orders: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Order' }],
  address: addressSchema, // Only one address per user
}, { timestamps: true });

module.exports = mongoose.model('User', userSchema);
