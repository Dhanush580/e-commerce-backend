const mongoose = require('mongoose');

const connectDB = async (mongoUri) => {
  await mongoose.connect(mongoUri);
};

module.exports = connectDB;
