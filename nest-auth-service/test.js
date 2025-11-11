import bcrypt from 'bcrypt'; // or const bcrypt = require('bcrypt');

async function run() {
  const password = '123456';
  const hash = await bcrypt.hash(password, 10);
  console.log('✅ New hash:', hash);

  const isMatch = await bcrypt.compare(password, hash);
  console.log('🔍 Compare result:', isMatch);
}

run();
