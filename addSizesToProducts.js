const mongoose = require('mongoose');
require('dotenv').config();

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI);

// Product Schema (updated with sizes)
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
	sizes: [{ 
		type: String, 
		required: false
	}],
	description: { type: String, required: true },
	inStock: { type: Boolean, default: true },
	createdAt: { type: Date, default: Date.now },
	updatedAt: { type: Date, default: Date.now }
});

const Product = mongoose.model('Product', productSchema);

async function addSizesToProducts() {
  try {
    console.log('Connecting to MongoDB...');
    
    // Find all products
    const allProducts = await Product.find({});
    
    console.log(`Found ${allProducts.length} products to update with sizes`);
    
    // Sample sizes for different categories
    const categoryDefaultSizes = {
      'bangles': ['2.4', '2.6', '2.8'],
      'rings': ['7', '8', '9', '10'],
      'sarees': ['Free Size', 'Regular'],
      'dresses': ['S', 'M', 'L', 'XL'],
      'earrings': ['Small', 'Medium'],
      'necklaces': ['16 inch', '18 inch'],
      'pendants': ['Medium'],
      'temple-jewellery': ['Medium', 'Large']
    };
    
    // Update each product with appropriate sizes
    for (const product of allProducts) {
      const defaultSizes = categoryDefaultSizes[product.category] || ['One Size'];
      
      await Product.findByIdAndUpdate(product._id, {
        sizes: defaultSizes,
        updatedAt: new Date()
      });
      
      console.log(`Updated product: ${product.name} (${product.category}) with sizes: ${defaultSizes.join(', ')}`);
    }
    
    console.log('All products updated with sizes!');
    
    // Display updated products
    const updatedProducts = await Product.find({}).select('name category sizes');
    console.log('\nUpdated products with sizes:');
    updatedProducts.forEach(product => {
      console.log(`- ${product.name} (${product.category}): ${product.sizes.join(', ')}`);
    });
    
  } catch (error) {
    console.error('Error updating products with sizes:', error);
  } finally {
    mongoose.connection.close();
  }
}

addSizesToProducts();