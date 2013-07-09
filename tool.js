
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



var rootCert = jsonCrypto.createCert('root', rootPair.publicPEM);

var signedRootCert = jsonCrypto.signObject(rootCert, rootPair.privatePEM, rootCert, false, log.wrap('signing root'));

var securityServicePair = jsonCrypto.generateKeyPEMBufferPair(MODULUS, EXPONENT);
var securityServiceFingerprint = jsonCrypto.createPublicKeyPEMFingerprintBuffer(securityServicePair.publicPEM);

var securityServiceCert = jsonCrypto.createCert('securityService', securityServicePair.publicPEM);

var signedSecurityServiceCert = jsonCrypto.signObject(securityServiceCert, rootPair.privatePEM, signedRootCert, false, log.wrap('signing security'));


fs.writeFileSync('./stage/rootPrivate.encodedpem', JSON.stringify(jsonCrypto.buffToJSONObject(rootPair.privatePEM, 'base64')));
fs.writeFileSync('./stage/rootPublic.encodedcert', JSON.stringify(signedRootCert));


fs.writeFileSync('./stage/securityPrivate.encodedpem', JSON.stringify(jsonCrypto.buffToJSONObject(securityServicePair.privatePEM, 'base64')));
fs.writeFileSync('./stage/securityPublic.encodedcert', JSON.stringify(signedSecurityServiceCert));


