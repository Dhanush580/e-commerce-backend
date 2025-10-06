const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

async function createAdmin() {
  console.log('🚀 Starting admin creation...');
  
  try {
    // Connect to MongoDB
    console.log('📡 Connecting to MongoDB...');
    await mongoose.connect('mongodb://localhost:27017/ecommerce');
    console.log('✅ Connected to MongoDB');

    // Define schemas directly here
    const adminSchema = new mongoose.Schema({
      email: { type: String, required: true, unique: true, lowercase: true, trim: true },
      password: { type: String, required: true },
      createdAt: { type: Date, default: Date.now },
    });

    const userSchema = new mongoose.Schema({
      email: { type: String, required: true, unique: true, lowercase: true, trim: true },
      role: { type: String, enum: ['user', 'admin'], default: 'user' },
      createdAt: { type: Date, default: Date.now },
    });

    const Admin = mongoose.model('Admin', adminSchema);
    const User = mongoose.model('User', userSchema);

    const adminEmail = 'pkveeragautham10@gmail.com';
    const adminPassword = 'admin123';

    console.log('🗑️ Cleaning up existing records...');
    await Admin.deleteMany({ email: adminEmail });
    await User.deleteMany({ email: adminEmail });

    console.log('🔐 Hashing password...');
    const hashedPassword = await bcrypt.hash(adminPassword, 10);
    console.log('✅ Password hashed successfully');

    console.log('📝 Creating admin record...');
    const admin = new Admin({
      email: adminEmail,
      password: hashedPassword
    });
    await admin.save();
    console.log('✅ Admin created in Admin collection');

    console.log('👤 Creating user record...');
    const user = new User({
      email: adminEmail,
      role: 'admin'
    });
    await user.save();
    console.log('✅ User created in User collection');

    // Verify
    const verifyAdmin = await Admin.findOne({ email: adminEmail });
    const verifyUser = await User.findOne({ email: adminEmail });

    console.log('\n🎉 SUCCESS! Admin created successfully!');
    console.log('📧 Email:', adminEmail);
    console.log('🔐 Password:', adminPassword);
    console.log('🆔 Admin ID:', verifyAdmin._id);
    console.log('🆔 User ID:', verifyUser._id);
    console.log('👤 User Role:', verifyUser.role);
    console.log('\n🌐 Admin Login URL: http://localhost:5173/admin/login');

  } catch (error) {
    console.error('❌ Error creating admin:');
    console.error('Error message:', error.message);
    console.error('Full error:', error);
  } finally {
    console.log('🔌 Closing database connection...');
    await mongoose.connection.close();
    process.exit(0);
  }
}

createAdmin();