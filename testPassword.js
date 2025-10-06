const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

async function testPassword() {
  try {
    const plainPassword = 'admin123';
    const hashedPassword = await bcrypt.hash(plainPassword, 10);
    
    console.log('Plain password:', plainPassword);
    console.log('Hashed password:', hashedPassword);
    
    const isValid = await bcrypt.compare(plainPassword, hashedPassword);
    console.log('Password comparison test:', isValid);
    
  } catch (error) {
    console.error('Error:', error);
  }
}

testPassword();