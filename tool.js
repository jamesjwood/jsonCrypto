
var EXPONENT = 65537;
var MODULUS = 2048;

var jsonCrypto = require('./index.js');
var utils = require('utils');
var log = utils.log().wrap('tool');

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


log(rootPair.privatePEM.toString());
log.dir(securityServiceCert);

log(securityServicePair.privatePEM.toString());
log.dir(signedSecurityServiceCert);

