// Run this script ONCE to migrate all user addresses from postalCode to pincode
// Usage: node backend/scripts/migrate_postalCode_to_pincode.js

const mongoose = require('mongoose');
const User = require('../models/User');

const MONGO_URI = 'mongodb://localhost:27017/YOUR_DB_NAME'; // <-- Change to your DB name

async function migrate() {
  await mongoose.connect(MONGO_URI);
  const users = await User.find({ 'address.postalCode': { $exists: true } });
  let updated = 0;
  for (const user of users) {
    if (user.address && user.address.postalCode && !user.address.pincode) {
      user.address.pincode = user.address.postalCode;
      user.address.postalCode = undefined;
      await user.save();
      updated++;
    }
  }
  console.log(`Migrated ${updated} users.`);
  await mongoose.disconnect();
}

migrate().catch(e => { console.error(e); process.exit(1); });
