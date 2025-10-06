const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

// User Schema (copy from your main file)
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String },
  role: { type: String, enum: ['user', 'admin'], default: 'user' }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

async function createAdmin() {
  try {
    // Connect to MongoDB
    await mongoose.connect('mongodb://localhost:27017/ecommerce', {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });

    console.log('Connected to MongoDB');

    const adminEmail = 'pkveeragautham10@gmail.com';
    const adminPassword = 'admin123';

    // Check if admin already exists
    const existingUser = await User.findOne({ email: adminEmail });
    
    if (existingUser) {
      console.log('User found:', { email: existingUser.email, role: existingUser.role, hasPassword: !!existingUser.password });
      
      if (existingUser.role === 'admin' && existingUser.password) {
        console.log('✅ Admin user already exists and is properly configured');
        console.log('Email:', adminEmail);
        console.log('Password: admin123');
        console.log('Role: admin');
        process.exit(0);
      } else {
        // Update existing user to admin with password
        console.log('Updating existing user to admin...');
        const hashedPassword = await bcrypt.hash(adminPassword, 10);
        existingUser.role = 'admin';
        existingUser.password = hashedPassword;
        await existingUser.save();
        console.log('✅ Updated existing user to admin with password!');
        console.log('Email:', adminEmail);
        console.log('Password: admin123');
        console.log('Role: admin');
        process.exit(0);
      }
    }

    // Create new admin user
    console.log('Creating new admin user...');
    const hashedPassword = await bcrypt.hash(adminPassword, 10);

    const adminUser = new User({
      email: adminEmail,
      password: hashedPassword,
      role: 'admin'
    });

    await adminUser.save();
    console.log('✅ Admin user created successfully!');
    console.log('Email:', adminEmail);
    console.log('Password: admin123');
    console.log('Role: admin');
    console.log('\nYou can now login to the admin panel at: http://localhost:3000/admin/login');

  } catch (error) {
    console.error('❌ Error creating admin:', error.message);
  } finally {
    await mongoose.connection.close();
    process.exit(0);
  }
}

createAdmin();