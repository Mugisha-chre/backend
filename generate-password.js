const bcrypt = require('bcryptjs');

// Generate password hash
const generateHash = async (password) => {
  const salt = await bcrypt.genSalt(10);
  const hash = await bcrypt.hash(password, salt);
  console.log('\n===========================================');
  console.log('PASSWORD HASH GENERATOR');
  console.log('===========================================');
  console.log('Password:', password);
  console.log('Hash:', hash);
  console.log('===========================================\n');
  return hash;
};

// Generate hash for default admin password
generateHash('admin123');