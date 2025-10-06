const mongoose = require('mongoose');

const productSchema = new mongoose.Schema({
  productId: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  images: [{ type: String, required: true }],
  price: { type: Number, required: true },
  category: {
    type: String,
    required: true,
    enum: ['earrings', 'necklaces', 'pendants', 'rings', 'temple-jewellery', 'bangles', 'sarees', 'dresses']
  },
  // Optional subcategory for accessories
  // Allowed values: victorian, cz-stone, silver, gold-plated
  subCategory: {
    type: String,
    enum: ['victorian', 'cz-stone', 'silver', 'gold-plated'],
    default: null
  },
  // sizes removed
  description: { type: String, required: true },
  inStock: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Product', productSchema);
