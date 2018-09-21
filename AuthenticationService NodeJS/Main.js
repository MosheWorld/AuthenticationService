var { JWTService } = require('./JWTService');

function getConfigurations(dataModel) {
    const configurations = {
        data: dataModel,
        secretKey: 'TW9zaGVFcmV6UHJpdmF0ZUtleQ==',
        expireDate: {
            expiresIn: '7d'
        }
    };

    return configurations;
}

(function main() {
    try {
        const model = {
            name: 'Moshe Binieli',
            email: 'mmoshikoo@gmail.com'
        };

        const configurations = getConfigurations(model);
        const jwtService = JWTService(configurations.secretKey);

        const token = jwtService.generateToken(configurations);

        if (!jwtService.isTokenValid(token, configurations.secretKey)) {
            throw new Error('Given token is not valid.');
        } else {
            const data = jwtService.getTokenData(token, configurations.secretKey);
            console.log(data);
        }
    } catch (ex) {
        console.error(ex);
    }
})();
