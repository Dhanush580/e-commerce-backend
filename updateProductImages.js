const mongoose = require('mongoose');
require('dotenv').config();

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI);

// Product Schema (same as in index.js)
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
	description: { type: String, required: true },
	inStock: { type: Boolean, default: true },
	createdAt: { type: Date, default: Date.now },
	updatedAt: { type: Date, default: Date.now }
});

const Product = mongoose.model('Product', productSchema);

async function updateProductImages() {
  try {
    console.log('Connecting to MongoDB...');
    
    // Find products with empty images arrays
    const productsWithEmptyImages = await Product.find({ 
      $or: [
        { images: { $exists: false } },
        { images: { $size: 0 } }
      ]
    });
    
    console.log(`Found ${productsWithEmptyImages.length} products with empty/missing images`);
    
    // Default images for different categories
    const defaultImages = {
      'rings': [
        'https://images.unsplash.com/photo-1605100804763-247f67b3557e?w=300&h=300&fit=crop',
        'https://images.unsplash.com/photo-1515562141207-7a88fb7ce338?w=300&h=300&fit=crop'
      ],
      'sarees': [
        'https://images.unsplash.com/photo-1583391265740-65681461cc7e?w=300&h=300&fit=crop',
        'https://images.unsplash.com/photo-1594736797933-d0802ba1ee65?w=300&h=300&fit=crop'
      ],
      'bangles': [
        'https://images.unsplash.com/photo-1515562141207-7a88fb7ce338?w=300&h=300&fit=crop',
        'https://images.unsplash.com/photo-1605100804763-247f67b3557e?w=300&h=300&fit=crop'
      ]
    };
    
    // Update each product
    for (const product of productsWithEmptyImages) {
      const categoryImages = defaultImages[product.category] || defaultImages['rings'];
      
      await Product.findByIdAndUpdate(product._id, {
        images: categoryImages,
        updatedAt: new Date()
      });
      
      console.log(`Updated product: ${product.name} (${product.category}) with ${categoryImages.length} images`);
    }
    
    console.log('All products updated successfully!');
    
    // Display updated products
    const allProducts = await Product.find({}).select('name category images');
    console.log('\nUpdated products:');
    allProducts.forEach(product => {
      console.log(`- ${product.name} (${product.category}): ${product.images.length} images`);
    });
    
  } catch (error) {
    console.error('Error updating products:', error);
  } finally {
    mongoose.connection.close();
  }
}

updateProductImages();