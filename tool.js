
var EXPONENT = 65537;
var MODULUS = 2048;

var jsonCrypto = require('./index.js');
var utils = require('utils');
var log = utils.log().wrap('tool');

var fs = require('fs');

//Generate root server pair

//Generate security Service server pair
var rootPair = jsonCrypto.generateKeyPEMBufferPair(MODULUS, EXPONENT);
var rootFingerprint = jsonCrypto.createPublicKeyPEMFingerprintBuffer(rootPair.publicPEM);

var rootCert = {
	name: 'collaborlist.com',
	id: rootFingerprint.toString('hex'),
	key: {
		data: rootPair.publicPEM.toString('utf8'),
		encoding: 'utf8'
	}
};

var securityServicePair = jsonCrypto.generateKeyPEMBufferPair(MODULUS, EXPONENT);
var securityServiceFingerprint = jsonCrypto.createPublicKeyPEMFingerprintBuffer(securityServicePair.publicPEM);

var securityServiceCert = {
	name: 'securityService.collaborlist.com',
	id: securityServiceFingerprint.toString('hex'),
	key: {
		data: securityServicePair.publicPEM.toString('utf8'),
		encoding: 'utf8'
	}
};

var signedSecurityServiceCert = jsonCrypto.signObject(securityServiceCert, rootPair.privatePEM, rootPair.publicPEM, log.wrap('signing'));


fs.writeFileSync('./stage/rootPrivate.pem', rootPair.privatePEM.toString());
fs.writeFileSync('./stage/rootPublic.pem', rootPair.publicPEM.toString());
fs.writeFileSync('./stage/rootPublic.json', JSON.stringify(securityServiceCert));


fs.writeFileSync('./stage/securityPrivate.pem', securityServicePair.privatePEM.toString());
fs.writeFileSync('./stage/securityPublic.pem', securityServicePair.publicPEM.toString());
fs.writeFileSync('./stage/securityPublic.json', JSON.stringify(signedSecurityServiceCert));


