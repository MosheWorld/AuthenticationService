const { JwtService } = require('./jwt-service');

const DEMO_JWT_SECRET = 'demo-only-secret-do-not-use-in-production';

function main() {
    // Demo only. Real applications should load a strong secret from secure configuration.
    const jwtService = new JwtService(DEMO_JWT_SECRET);
    const payload = {
        name: 'Moshe Binieli',
        email: 'mmoshikoo@gmail.com'
    };

    try {
        const token = jwtService.generateToken(payload, { expiresIn: '7d' });
        const verifiedPayload = jwtService.verifyToken(token);

        console.log('Token:', token);
        console.log('Verified payload:', verifiedPayload);
    } catch (error) {
        console.error('JWT operation failed:', error.message);
    }
}

main();
