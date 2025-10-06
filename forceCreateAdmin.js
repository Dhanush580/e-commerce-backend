const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

// User Schema (matching the main backend)
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String }, // Optional password field for admin users
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  createdAt: { type: Date, default: Date.now },
});

const User = mongoose.model('User', userSchema);

async function forceCreateAdmin() {
  try {
    // Connect to MongoDB
    await mongoose.connect('mongodb://localhost:27017/ecommerce', {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });

    console.log('✅ Connected to MongoDB');

    const adminEmail = 'pkveeragautham10@gmail.com';
    const adminPassword = 'admin123';

    // Delete existing user with this email
    const deleteResult = await User.deleteOne({ email: adminEmail });
    if (deleteResult.deletedCount > 0) {
      console.log('🗑️ Deleted existing user with email:', adminEmail);
    }

    // Create new admin user
    console.log('🔧 Creating new admin user...');
    const hashedPassword = await bcrypt.hash(adminPassword, 10);

    const adminUser = new User({
      email: adminEmail,
      password: hashedPassword,
      role: 'admin'
    });

    await adminUser.save();
    
    // Verify the admin was created
    const verifyAdmin = await User.findOne({ email: adminEmail });
    console.log('✅ Admin user created and verified!');
    console.log('📧 Email:', verifyAdmin.email);
    console.log('🔐 Password: admin123');
    console.log('👤 Role:', verifyAdmin.role);
    console.log('🔑 Has Password:', !!verifyAdmin.password);
    console.log('📅 Created:', verifyAdmin.createdAt);
    console.log('\n🌐 You can now login to the admin panel at: http://localhost:3000/admin/login');

  } catch (error) {
    console.error('❌ Error creating admin:', error.message);
    console.error(error);
  } finally {
    await mongoose.connection.close();
    process.exit(0);
  }
}

console.log('🚀 Force creating admin user...');
forceCreateAdmin();