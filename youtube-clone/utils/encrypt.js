const crypto = require('crypto');



// AES encryption function
function encrypt(text) {
  const secretKey = process.env.SECRET;
  const iv = process.env.IV;
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(secretKey), Buffer.from(iv, 'hex'));
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}

function decrypt(encryptedData) {
  const secretKey = process.env.SECRET;
  const iv = process.env.IV;
  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(secretKey), Buffer.from(iv, 'hex'));
  let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

module.exports = {encrypt,decrypt}


