const jwt = require('jsonwebtoken');

class JwtService {
    constructor(secretKey) {
        this.secretKey = secretKey;
    }

    /**
     * @param {import('jsonwebtoken').JwtPayload} payload
     * @param {import('jsonwebtoken').SignOptions} [options]
     * @returns {string}
     */
    generateToken(payload, options = {}) {
        return jwt.sign(payload, this.secretKey, {
            ...options,
            algorithm: 'HS256'
        });
    }

    /**
     * @param {string} token
     * @returns {import('jsonwebtoken').JwtPayload}
     */
    verifyToken(token) {
        const payload = jwt.verify(token, this.secretKey, {
            algorithms: ['HS256']
        });

        if (typeof payload === 'string') {
            throw new jwt.JsonWebTokenError('Expected the token payload to be an object.');
        }

        return payload;
    }
}

module.exports = { JwtService };
