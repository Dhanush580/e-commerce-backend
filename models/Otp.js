const mongoose = require('mongoose');

const otpSchema = new mongoose.Schema({
  email: { type: String, required: true },
  code: { type: String, required: true },
  expiresAt: { type: Date, required: true },
  attempts: { type: Number, default: 0 },
});
otpSchema.index({ email: 1 });

module.exports = mongoose.models.Otp || mongoose.model('Otp', otpSchema);
