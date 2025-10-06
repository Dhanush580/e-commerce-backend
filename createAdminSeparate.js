const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

// User Schema (same as main backend)
const userSchema = new mongoose.Schema({
	email: { type: String, required: true, unique: true, lowercase: true, trim: true },
	role: { type: String, enum: ['user', 'admin'], default: 'user' },
	createdAt: { type: Date, default: Date.now },
});

// Admin Schema (separate collection for admin credentials)
const adminSchema = new mongoose.Schema({
	email: { type: String, required: true, unique: true, lowercase: true, trim: true },
	password: { type: String, required: true },
	createdAt: { type: Date, default: Date.now },
});

const User = mongoose.model('User', userSchema);
const Admin = mongoose.model('Admin', adminSchema);

async function createAdminUser() {
  try {
    // Connect to MongoDB
    await mongoose.connect('mongodb://localhost:27017/ecommerce', {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });

    console.log('✅ Connected to MongoDB');

    const adminEmail = 'pkveeragautham10@gmail.com';
    const adminPassword = 'admin123';

    // Clean up existing admin records
    await Admin.deleteOne({ email: adminEmail });
    await User.deleteOne({ email: adminEmail });
    console.log('🗑️ Cleaned up existing admin records');

    // Create admin credentials in Admin collection
    const hashedPassword = await bcrypt.hash(adminPassword, 10);
    const admin = await Admin.create({
      email: adminEmail,
      password: hashedPassword
    });

    // Create corresponding user with admin role
    const user = await User.create({
      email: adminEmail,
      role: 'admin'
    });

    console.log('✅ Admin user created successfully!');
    console.log('📧 Email:', adminEmail);
    console.log('🔐 Password:', adminPassword);
    console.log('👤 Role: admin');
    console.log('🔧 Admin ID:', admin._id);
    console.log('👤 User ID:', user._id);
    console.log('\n🌐 You can now login to admin panel at: http://localhost:5173/admin/login');

    // Verify everything was created correctly
    const verifyAdmin = await Admin.findOne({ email: adminEmail });
    const verifyUser = await User.findOne({ email: adminEmail });
    
    console.log('\n✅ Verification:');
    console.log('Admin in Admin collection:', !!verifyAdmin);
    console.log('User in User collection:', !!verifyUser);
    console.log('User has admin role:', verifyUser?.role === 'admin');

  } catch (error) {
    console.error('❌ Error creating admin:', error.message);
    console.error(error);
  } finally {
    await mongoose.connection.close();
    process.exit(0);
  }
}

console.log('🚀 Creating admin user with separate Admin schema...');
createAdminUser();