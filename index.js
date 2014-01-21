/*global window */
/*global forge */
/*jslint node: true */




var assert = require('assert');
var stringify = require('canonical-json');
var utils = require('utils');
var is = utils.is;

var Buff = require('buffer').Buffer;

var DEFAULT_ENCODING = 'base64';
var DEFAULT_HASH_METHOD = 'sha256';

//probably a better way to do this but the below works for browserify

var Forge;

if(typeof forge !== 'undefined')
{
	Forge = forge;
}
else
{
	Forge = require('node-forge');
}


var pki = Forge.pki;
var rsa = pki.rsa;




var copyObject= function copyObject(object){
	var copy =  JSON.parse(JSON.stringify(object));
	return copy;
};

var createSignableObject = function createSignableObject(object){
	var copy = copyObject(object);
	delete copy.signature;
	for(var name in copy)
	{
		if(name.substr(0,1) === "_")
		{
			delete copy[name];
		}
	}
	return copy;
};
var hashBufferToDigest = function hashBufferToDigest(dataBuffer, hashMethod){
	var md = Forge.md[hashMethod].create();
	md.update(dataBuffer.toString('utf8'), 'utf8');
	return md;
};

var hashDigestToBuffer = function hashDigestToBuffer(md){
	var hashBuf = new Buff(md.digest().toHex(), 'hex');
	return hashBuf;
};

module.exports.hashBuffer = function hashBuffer(dataBuffer, hashMethod){
	var md = hashBufferToDigest(dataBuffer, hashMethod);
	var hashBuf = new Buff(md.digest().toHex(), 'hex');
	return hashBuf;
};


module.exports.generateKeyPEMBufferPair = function generateKeyPEMBufferPair(modulus, exponent)
{
	var keypair = rsa.generateKeyPair(modulus, exponent);
	var publicPEMBuffer = new Buff(pki.publicKeyToPem(keypair.publicKey), 'utf8');
	var privatePEMBuffer = new Buff(pki.privateKeyToPem(keypair.privateKey), 'utf8');
	return {publicPEM: publicPEMBuffer, privatePEM: privatePEMBuffer};
};


module.exports.hashAndSignBuffer = function hashAndSignBuffer(dataBuffer, privateKeyPEMBuffer, log){
	assert.ok(dataBuffer);
	assert.ok(privateKeyPEMBuffer);
	assert.ok(log);


	log('reading private key');
	var privateKey = pki.privateKeyFromPem(privateKeyPEMBuffer.toString('utf8'));

	var hashDigest = hashBufferToDigest(dataBuffer, DEFAULT_HASH_METHOD);
	var hashBuffer = hashDigestToBuffer(hashDigest);

	log('getting hash bytes');
	var hashBytes = Forge.util.hexToBytes(hashBuffer.toString('hex'), 'hex');

	log('getting signature bytes');
	var sigBytes =privateKey.sign(hashDigest);

	log('creating output buffer');

	var sigHex = Forge.util.createBuffer(sigBytes).toHex();
	var sigBuf = new Buff(sigHex, 'hex');
	return sigBuf;
};

module.exports.hashAndVerifyBuffer = function hashAndVerifyBuffer(hashBuffer, publicKeyPEMBuffer, signatureBuffer){
	var hashBytes = Forge.util.hexToBytes(hashBuffer.toString('hex'), 'hex');
	var publicKey = pki.publicKeyFromPem(publicKeyPEMBuffer.toString('utf8'));
	var sigHex = signatureBuffer.toString('hex');
	var sigBytes = Forge.util.hexToBytes(sigHex);
	var verified = publicKey.verify(hashBytes, sigBytes);
	return verified;
};

module.exports.createPublicKeyPEMFingerprintBuffer = function createPublicKeyPEMFingerprintBuffer(publicKeyPEMBuff)
{
	assert.ok(publicKeyPEMBuff);
	var fingerBuff = module.exports.hashBuffer(publicKeyPEMBuff,'sha1');
	return fingerBuff;
};


module.exports.createSignature = function createSignature(object, privateKeyPEMBuffer, publicCert, includeSigner, log){
	var objectString = stringify(object);
	var objectBuff = new Buff(objectString);
	if(!includeSigner)
	{
		throw new Error('includeSigner false no loger supported');
	}

	log('hashing');
	var hashBuf = module.exports.hashBuffer(objectBuff, DEFAULT_HASH_METHOD);
	log('signing');
	var sigBuf = module.exports.hashAndSignBuffer(objectBuff, privateKeyPEMBuffer, log.wrap('sign buffer'));

	log('creating signature');

	var that = {
		signed: module.exports.buffToJSONObject(sigBuf, DEFAULT_ENCODING),
		digest: module.exports.buffToJSONObject(hashBuf, DEFAULT_ENCODING),
		digestMethod: DEFAULT_HASH_METHOD,
		date: new Date(),
	};

	if(includeSigner)
	{
		that.signer= publicCert;
	}
	else
	{
		that.signer= module.exports.createPublicKeyPEMFingerprintBuffer(module.exports.jSONObjectToBuffer(publicCert.key)).toString('base64');
	}
	return that;
};
module.exports.getTrustedCert = function getTrustedCert(certOrFingerprint, trustedCerts){
	var foundCert;
	trustedCerts.map(function(trustedCert){
		if((typeof certOrFingerprint === 'object' && trustedCert.id === certOrFingerprint.id) || (typeof certOrFingerprint === 'string' && trustedCert.id === certOrFingerprint))
		{
			foundCert = trustedCert;
		}
	});
	return foundCert;
};

module.exports.verifySignature = function verifySignature(signature, object, log){
	assert.ok(signature.signer, 'signature must have a signer');
	var publicCert = signature.signer;


	var publicKeyPEMBuffer = module.exports.jSONObjectToBuffer(publicCert.key);
	var publicKey = pki.publicKeyFromPem(publicKeyPEMBuffer.toString('utf8'));

	var objectString = stringify(object);
	var objectBuff = new Buff(objectString);

	var hashBuf = module.exports.hashBuffer(objectBuff, signature.digestMethod);
	var existingHashBuf = module.exports.jSONObjectToBuffer(signature.digest);

	if(hashBuf.toString(DEFAULT_ENCODING) !==  existingHashBuf.toString(DEFAULT_ENCODING)){
		log('hash not ok');
		return false;
	}

	log('hash ok, checking signature');

	var signatureBuff = module.exports.jSONObjectToBuffer(signature.signed);

	var verified = module.exports.hashAndVerifyBuffer(hashBuf, publicKeyPEMBuffer, signatureBuff);
	return verified;
};

module.exports.signObject = function signObject(object, privateKeyPEMBuffer, publicCert, includeSigner, log){
	var signable = createSignableObject(object);
	var copy = copyObject(object);
	copy.signature = module.exports.createSignature(signable, privateKeyPEMBuffer, publicCert, includeSigner, log);
	return copy;
};

module.exports.verifyObjectIsSigned = function verifyObjectIsSigned(object, log){
	if(!object.signature)
	{
		return false;
	}
	assert.ok(object.signature.signed, 'a signature must have signature data:' + JSON.stringify(object));
	assert.ok(object.signature.signer, 'a signature must have the signing cert as signer');
	var signature = object.signature;
	var copy = createSignableObject(object);

	var verified = module.exports.verifySignature(signature, copy, log);
	return verified;
};


module.exports.verifyObject = function verifyObject(object, log){
	try
	{
		assert.ok(object);
		var verifiedSignature = module.exports.verifyObjectIsSigned(object, log.wrap('verifyObjectIsSigned'));
		if(verifiedSignature)
		{
			return module.exports.verifyObject.SIGNATURE_VALID;
		}
		else
		{
			return module.exports.verifyObject.SIGNATURE_INVALID;
		}
	}
	catch (e)
	{
		e.message = 'Error in jsonCrypto.verifyObject(): ' + e.message;
		throw e;
	}
};

module.exports.verifyObject.SIGNATURE_INVALID = 0;
module.exports.verifyObject.SIGNATURE_VALID = 2;


module.exports.encrypt = function encrypt(object, fieldsToBeEncrypted, rsaKeys, log){
	var copy = copyObject(object);

	fieldsToBeEncrypted.forEach(function(name){
		log('encrypting: ' + name);
		if(typeof copy[name] !== 'undefined')
		{
			var valueString = JSON.stringify(copy[name]);
			var valueBuffer = new Buff(valueString, 'utf8');
			copy[name] = module.exports.encryptJSON(valueBuffer, rsaKeys, log);
		}
	});

	return copy;
};

module.exports.encrypt2 = function encrypt2(object, fieldsToBeEncrypted, rsaKeys, log){
	var copy = copyObject(object);

	var objectToBeEncrypted = {};

	fieldsToBeEncrypted.forEach(function(name){
		if(typeof copy[name] !== 'undefined')
		{
			objectToBeEncrypted[name] = copy[name];
			delete copy[name];
		}
	});

	var valueBuffer = new Buff(JSON.stringify(objectToBeEncrypted), 'utf8');
	copy.encrypted =  module.exports.encryptValue(valueBuffer, rsaKeys, log);

	return copy;
};

module.exports.decrypt2 = function decrypt2(object, fingerprintHex, privatePEMBuffer, log){
	var copy = copyObject(object);
	assert.ok(copy.encrypted);
	var encrypted = copy.encrypted;
	delete copy.encrypted;

	var unencryptedBuffer = module.exports.decryptValue(encrypted, fingerprintHex, privatePEMBuffer, log);
	var unencrypted = JSON.parse(unencryptedBuffer.toString('utf8'));

	for(var name in unencrypted)
	{
		copy[name] = unencrypted[name];
	}
	return copy;
};

module.exports.decrypt = function decrypt(object, fieldsToBeDecrypyted, fingerprintHex, privatePEMBuffer, log){
	var copy = copyObject(object);
	fieldsToBeDecrypyted.forEach(function(name){
		if(typeof copy[name] !== 'undefined')
		{
			var decryptedBuffer = module.exports.decryptJSON(copy[name], fingerprintHex, privatePEMBuffer, log);
			var value = JSON.parse(decryptedBuffer.toString('utf8'));
			copy[name] = value;
		}
	});

	return copy;
};


module.exports.buffToJSONObject = function buffToJSONObject(buffer){
	var obj = {
		value: buffer.toString(DEFAULT_ENCODING),
		encoding: DEFAULT_ENCODING
	};
	return obj;
};

module.exports.jSONObjectToBuffer = function jSONObjectToBuffer(object){
	var B  = new Buff(object.value, object.encoding);
	return B;
};

module.exports.getRandomBuffer = function getRandomBuffer(bytes){
	var randomBytes = Forge.random.getBytesSync(bytes);
	var randomBuffer = new Buff(Forge.util.bytesToHex(randomBytes), 'hex');
	return randomBuffer;
};

module.exports.verifyCertificateAndPrivateKeys = function(cert, privateKeyBuffer, log){
	utils.is.object(cert);
	utils.is.object(privateKeyBuffer);
	utils.is.fn(log);

	var myBuff = new Buffer("hello");

	var publicKeyBuffer = module.exports.jSONObjectToBuffer(cert.key);

	try{
		var encrypted = module.exports.encryptRSA(myBuff, publicKeyBuffer, log.wrap('encryptRSA'));
		var decrypted = module.exports.decryptRSA(encrypted, privateKeyBuffer, log.wrap('decryptRSA'));
		if (decrypted.toString() === 'hello')
		{
			return true;
		}
		else
		{
			return false;
		}
	}
	catch(error)
	{
		return false;
	}
};

module.exports.encryptRSA = function encryptRSA(secretBuffer, publicKeyBuffer, log)
{
	var publicKey = pki.publicKeyFromPem(publicKeyBuffer.toString('utf8'));
	var secretBytes = Forge.util.hexToBytes(secretBuffer.toString('hex'));

	var encodedKeyBytes = publicKey.encrypt(secretBytes);
	var encodedKeyBuffer =  new Buff(Forge.util.bytesToHex(encodedKeyBytes), 'hex');
	return encodedKeyBuffer;
};

module.exports.decryptRSA = function decryptRSA(encryptedBuffer, privateKeyBuffer, log){
	var privateKey = pki.privateKeyFromPem(privateKeyBuffer.toString('utf8'));
	var encryptedBytes = Forge.util.hexToBytes(encryptedBuffer.toString('hex'));
	var decryptedBytes = privateKey.decrypt(encryptedBytes);
	var decryptedBuffer = new Buff(Forge.util.bytesToHex(decryptedBytes), 'hex');
	return decryptedBuffer;
};
module.exports.encryptAES = function encryptAES(toBeEncryptedBuff, aesKeyBuffer, log){
	var ivBuff = module.exports.getRandomBuffer(16);
	var ivBytes = Forge.util.hexToBytes(ivBuff.toString('hex'));
	var aesKeyBytes = Forge.util.hexToBytes(aesKeyBuffer.toString('hex'));

	var cipher = Forge.aes.createEncryptionCipher(aesKeyBytes);
	cipher.start(ivBytes);
	cipher.update(Forge.util.createBuffer(toBeEncryptedBuff.toString('utf8')));
	cipher.finish();
	var encryptedData = cipher.output;
	var encryptedDataBuff = new Buff(encryptedData.toHex(), 'hex');
	var encrypted = {
		method: 'aes',
		data: module.exports.buffToJSONObject(encryptedDataBuff),
		iv: module.exports.buffToJSONObject(ivBuff)
	};
	return encrypted;
};

module.exports.decryptAES = function decryptAES(encrypted, aesKeyBuffer, log){
	is.object(aesKeyBuffer, 'aesKeyBuffer');
	is.function(log, 'log');
	is.object(encrypted, 'encrypted');
	is.object(encrypted.data, 'encrypted.data');
	is.string(encrypted.method, 'encrypted.method');
	is.object(encrypted.iv, 'encrypted.iv');


	var encryptedDataBuffer = module.exports.jSONObjectToBuffer(encrypted.data);

	var ivBuffer = module.exports.jSONObjectToBuffer(encrypted.iv);
	var ivBytes = Forge.util.hexToBytes(ivBuffer.toString('hex'));

	var encryptedDataBytes = Forge.util.hexToBytes(encryptedDataBuffer.toString('hex'));

	var aesKeyHex = aesKeyBuffer.toString('hex');


	assert.ok(aesKeyHex.length === 32, 'AES key length must be 32');


	var cipher;
	try
	{
		log('trying to generate cipher from aeskey: ' + aesKeyHex);
		var aesKeyBytes = Forge.util.hexToBytes(aesKeyHex);
		cipher = Forge.aes.createDecryptionCipher(aesKeyBytes);
	}
	catch(err)
	{
		var e = new Error('Error creating decryption cipher, bad AES key: ' + aesKeyHex);
		e.inner = err;
		e.code = 8000;
		throw e;
	}
	
	try
	{
		log('trying the decrypt the data');
		cipher.start(ivBytes);
		cipher.update(Forge.util.createBuffer(encryptedDataBytes));
		cipher.finish();
	}
	catch(err)
	{
		var e = new Error('Error decrypting data');
		e.inner = err;
		e.code = 8001;
		throw e;
	}

	var decryptedHex = cipher.output.toHex();
	var decryptedBuff = new Buff(decryptedHex, 'hex');
	return decryptedBuff;

};

module.exports.encryptJSON  = function encryptJSON(jsonBuff, rsaKeys, log){
	var aesKeyBuffer = module.exports.getRandomBuffer(16);
	var encrypted = module.exports.encryptAES(jsonBuff, aesKeyBuffer, log.wrap('encryptAES'));
	encrypted.keys = {};

	for(var fingerprint in rsaKeys)
	{
		var publicKeyPEMBuffer  = module.exports.jSONObjectToBuffer(rsaKeys[fingerprint]);
		var encodedKeyBuffer = module.exports.encryptRSA(aesKeyBuffer, publicKeyPEMBuffer, log);
		encrypted.keys[fingerprint] = module.exports.buffToJSONObject(encodedKeyBuffer);
	}

	return encrypted;
};

module.exports.decryptJSON = function decryptJSON(encrypted, fingerprintHex, privateKeyPEMBuff, log){

	assert.ok(encrypted.keys);
	assert.ok(fingerprintHex);
	assert.ok(privateKeyPEMBuff);

	var privateKey = pki.privateKeyFromPem(privateKeyPEMBuff.toString('utf8'));

	var encryptedAESKey = encrypted.keys[fingerprintHex];
	assert.ok(encryptedAESKey);

	var encryptedAESKeyBuffer = module.exports.jSONObjectToBuffer(encryptedAESKey);
	var decryptedAESKeyBuffer = module.exports.decryptRSA(encryptedAESKeyBuffer, privateKeyPEMBuff, log.wrap('decrypting aes key'));

	var decryptedBuff = module.exports.decryptAES(encrypted, decryptedAESKeyBuffer, log.wrap('decryptAES'));

	return decryptedBuff;
};

module.exports.createCert = function createCert(publicPEMBuffer){
	var fingerprint = module.exports.createPublicKeyPEMFingerprintBuffer(publicPEMBuffer);
	var cert = {
		id: fingerprint.toString('base64'),
		key: module.exports.buffToJSONObject(publicPEMBuffer, 'utf8')
	};
	return cert;
};

var powFormat = 'hex';


var createPOWObject = function createPOWObject(object){
	var copy = copyObject(object);
	delete copy.proofOfWork;
	delete copy._rev;
	return copy;
};

module.exports.validateProofOfWork = function validateProofOfWork(object){
	var proofOfWork = object.proofOfWork;
	assert.ok(proofOfWork, 'proofOfWork required');
	var precision = proofOfWork.precision;
	var hashMethod = proofOfWork.method;
	var value = proofOfWork.value;
	assert.ok(precision, 'precision required');
	assert.ok(hashMethod, 'hashMethod required');
	assert.ok(value, 'value required');

	var precisionCheckString ='';
	for(var i =0; i < precision; i ++)
	{
		precisionCheckString = precisionCheckString + '0';
	}

	var copy = createPOWObject(object);
	var objectString = stringify(copy);

	var toBeHashedBuffer = new Buff(objectString + value.toString());
	var hashedBuffer = module.exports.hashBuffer(toBeHashedBuffer, hashMethod);
	var hashedHex = hashedBuffer.toString(powFormat);

	var concat = hashedHex.substr(0, precision);
	return (concat === precisionCheckString);
};


module.exports.addProofOfWork = function addProofOfWork(object, options){
	options = options ||{};
	var hashMethod = options.method || 'sha256';
	var precision= options.precision || 4;

	var precisionCheckString = '';
	for(var i =0; i < precision; i ++)
	{
		precisionCheckString = precisionCheckString + '0';
	}
	var copy = createPOWObject(object);
	var objectString = stringify(copy);
	var found = false;
	var value = 0;
	var toBeHashedBuffer;
	while (!found)
	{
		toBeHashedBuffer = new Buff(objectString + value.toString());
		var hashedBuffer = module.exports.hashBuffer(toBeHashedBuffer, hashMethod);
		var hashedHex = hashedBuffer.toString(powFormat);
		var concat = hashedHex.substr(0, precision);
		if(concat === precisionCheckString)
		{
			found = true;
		}
		else
		{
			value++;
		}
	}
	copy.proofOfWork = {method: 'sha256', value: value, precision: precision};
	return copy;
};

var crypto = require('crypto');

module.exports.addProofOfWorkNode = function addProofOfWorkNode(object, options){
	options = options ||{};
	var hashMethod = options.method || 'sha256';
	var precision= options.precision || 4;



	

	var precisionCheckString = '';
	for(var i =0; i < precision; i ++)
	{
		precisionCheckString = precisionCheckString + '0';
	}
	var copy = copyObject(object);
	delete copy.proofOfWork;
	var objectString = stringify(copy);
	var found = false;
	var value = 0;
	var toBeHashedBuffer;
	while (!found)
	{

		toBeHashedBuffer = new Buff(objectString + value.toString());

		var shasum = crypto.createHash('sha256');
		shasum.update(toBeHashedBuffer);

		var hashedHex = shasum.digest(powFormat);
		var concat = hashedHex.substr(0, precision);
		if(concat === precisionCheckString)
		{
			found = true;
		}
		else
		{
			value++;
		}
	}
	copy.proofOfWork = {method: 'sha256', value: value, precision: precision};
	return copy;
};



