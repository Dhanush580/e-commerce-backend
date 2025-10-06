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

async function updateToSingleImage() {
  try {
    console.log('Connecting to MongoDB...');
    
    // Find all products
    const allProducts = await Product.find({});
    
    console.log(`Found ${allProducts.length} products to update`);
    
    // Update each product to use only the first image
    for (const product of allProducts) {
      if (product.images && product.images.length > 0) {
        // Keep only the first image
        const singleImage = product.images[0];
        
        await Product.findByIdAndUpdate(product._id, {
          images: [singleImage],
          updatedAt: new Date()
        });
        
        console.log(`Updated product: ${product.name} - kept first image: ${singleImage}`);
      }
    }
    
    console.log('All products updated to single image!');
    
    // Display updated products
    const updatedProducts = await Product.find({}).select('name category images');
    console.log('\nUpdated products:');
    updatedProducts.forEach(product => {
      console.log(`- ${product.name} (${product.category}): ${product.images.length} image(s) - ${product.images[0]}`);
    });
    
  } catch (error) {
    console.error('Error updating products:', error);
  } finally {
    mongoose.connection.close();
  }
}

updateToSingleImage();