
const jwt = require('jsonwebtoken');

function generateToken(user) {
    // Hardcoded JWT Secret
    const JWT_SECRET = "my_super_secret_jwt_key_12345_2";
    return jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '1h' });
}
