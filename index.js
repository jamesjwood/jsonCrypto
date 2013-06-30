/*global window */
/*jslint node: true */

var Forge = require('node-forge');
var rsa = Forge.pki.rsa;
var pki = Forge.pki;
var assert = require('assert');
var stringify = require('canonical-json');

var Buff = require('buffer').Buffer;

var DEFAULT_ENCODING = 'base64';
var DEFAULT_HASH_METHOD = 'sha256';

//probably a better way to do this but the below works for browserify
if(typeof window !== 'undefined')
{
	require('./node_modules/node-forge/js/pkcs7asn1.js');
	require('./node_modules/node-forge/js/mgf.js');
	require('./node_modules/node-forge/js/mgf1.js');
	require('./node_modules/node-forge/js/md.js');
	require('./node_modules/node-forge/js/tls.js');
	require('./node_modules/node-forge/js/task.js');
	require('./node_modules/node-forge/js/rc2.js');
	require('./node_modules/node-forge/js/pss.js');
	require('./node_modules/node-forge/js/pkcs7.js');
	require('./node_modules/node-forge/js/pkcs12.js');
	require('./node_modules/node-forge/js/pbkdf2.js');
	require('./node_modules/node-forge/js/log.js');
	require('./node_modules/node-forge/js/aesCipherSuites.js');
	require('./node_modules/node-forge/js/des.js');
	require('./node_modules/node-forge/js/debug.js');
	require('./node_modules/node-forge/js/util.js');
	require('./node_modules/node-forge/js/md5.js');
	require('./node_modules/node-forge/js/sha1.js');
	require('./node_modules/node-forge/js/sha256.js');
	require('./node_modules/node-forge/js/prng.js');
	require('./node_modules/node-forge/js/random.js');
	require('./node_modules/node-forge/js/hmac.js');
	require('./node_modules/node-forge/js/jsbn.js');
	require('./node_modules/node-forge/js/oids.js');
	require('./node_modules/node-forge/js/asn1.js');
	require('./node_modules/node-forge/js/rsa.js');
	require('./node_modules/node-forge/js/pki.js');
	require('./node_modules/node-forge/js/aes.js');
}





var copyObject= function(object){
	var copy =  JSON.parse(JSON.stringify(object));
	return copy;
};

var createSignableObject = function(object){
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
var hashBufferToDigest = function(dataBuffer, hashMethod){
	var md = Forge.md[hashMethod].create();
	md.update(dataBuffer.toString('utf8'), 'utf8');
	return md;
};

var hashDigestToBuffer = function(md){
	var hashBuf = new Buff(md.digest().toHex(), 'hex');
	return hashBuf;
};

module.exports.hashBuffer = function(dataBuffer, hashMethod){
	var md = hashBufferToDigest(dataBuffer, hashMethod);
	var hashBuf = new Buff(md.digest().toHex(), 'hex');
	return hashBuf;
};


module.exports.generateKeyPEMBufferPair = function(modulus, exponent)
{
	var keypair = rsa.generateKeyPair(modulus, exponent);
	var publicPEMBuffer = new Buff(pki.publicKeyToPem(keypair.publicKey), 'utf8');
	var privatePEMBuffer = new Buff(pki.privateKeyToPem(keypair.privateKey), 'utf8');
	return {publicPEM: publicPEMBuffer, privatePEM: privatePEMBuffer};
};


module.exports.hashAndSignBuffer = function(dataBuffer, privateKeyPEMBuffer, log){
	assert.ok(dataBuffer);
	assert.ok(privateKeyPEMBuffer);
	assert.ok(log);


	log('reading private key');
	log(privateKeyPEMBuffer.toString('utf8'));
	var privateKey = pki.privateKeyFromPem(privateKeyPEMBuffer.toString('utf8'));

	var hashDigest = hashBufferToDigest(dataBuffer, DEFAULT_HASH_METHOD);
	log.dir(hashDigest);
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

module.exports.hashAndVerifyBuffer = function(hashBuffer, publicKeyPEMBuffer, signatureBuffer){
	var hashBytes = Forge.util.hexToBytes(hashBuffer.toString('hex'), 'hex');
	var publicKey = pki.publicKeyFromPem(publicKeyPEMBuffer.toString('utf8'));
	var sigHex = signatureBuffer.toString('hex');
	var sigBytes = Forge.util.hexToBytes(sigHex);
	var verified = publicKey.verify(hashBytes, sigBytes);
	return verified;
};

module.exports.createPublicKeyPEMFingerprintBuffer = function(publicKeyPEMBuff)
{
	assert.ok(publicKeyPEMBuff);
	var fingerBuff = module.exports.hashBuffer(publicKeyPEMBuff,'md5');
	return fingerBuff;
};


module.exports.createSignature = function(object, privateKeyPEMBuffer, publicCert, log){
	var objectString = stringify(object);
	var objectBuff = new Buff(objectString);

	log('hashing');
	var hashBuf = module.exports.hashBuffer(objectBuff, DEFAULT_HASH_METHOD);
	log('signing');
	var sigBuf = module.exports.hashAndSignBuffer(objectBuff, privateKeyPEMBuffer, log.wrap('sign buffer'));
	log('reading public key');

	log('creating signature');

	var that = {
		digest: hashBuf.toString(DEFAULT_ENCODING),
		date: new Date(),
		digestEncoding: DEFAULT_ENCODING,
		digestMethod: DEFAULT_HASH_METHOD,
		signed: sigBuf.toString(DEFAULT_ENCODING),
		signedEncoding: DEFAULT_ENCODING,
		signer: publicCert
	};
	return that;
};

module.exports.verifySignature = function(signature, object, log){

	var publicCert = signature.signer;
	var publicKeyPEMBuffer = module.exports.jSONObjectToBuffer(publicCert.key);
	var publicKey = pki.publicKeyFromPem(publicKeyPEMBuffer.toString('utf8'));

	var objectString = stringify(object);
	var objectBuff = new Buff(objectString);

	var hashBuf = module.exports.hashBuffer(objectBuff, signature.digestMethod);

	if(hashBuf.toString(signature.digestEncoding) !== signature.digest){
		log('hash not ok');
		return false;
	}

	log('hash ok, checking signature');

	var signatureBuff = new Buff(signature.signed, signature.signedEncoding);

	var verified = module.exports.hashAndVerifyBuffer(hashBuf, publicKeyPEMBuffer, signatureBuff);
	return verified;
};

module.exports.signObject = function(object, privateKeyPEMBuffer, publicCert, log){
	var copy = createSignableObject(object);

	object.signature = module.exports.createSignature(copy, privateKeyPEMBuffer, publicCert, log);
	return object;
};

module.exports.verifyObjectIsSigned = function(object, log){
	var signature = object.signature;
	var copy = createSignableObject(object);

	var verified = module.exports.verifySignature(signature, copy, log);
	return verified;
};

module.exports.verifyObject = function(object, rootCert, log){
	var verifiedSignature = module.exports.verifyObjectIsSigned(object, log.wrap('verifyObjectIsSigned'));
	if(verifiedSignature)
	{
		return module.exports.verifyCertificateChain(object.signature.signer, rootCert, log.wrap('verifyCertificateChain'));
	}
	else
	{
		return false;
	}
};

module.exports.encrypt = function(object, fieldsToBeEncrypted, rsaKeys, log){
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

module.exports.encrypt2 = function(object, fieldsToBeEncrypted, rsaKeys, log){
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

module.exports.decrypt2 = function(object, fingerprintHex, privatePEMBuffer, log){
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

module.exports.decrypt = function(object, fieldsToBeDecrypyted, fingerprintHex, privatePEMBuffer, log){
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


module.exports.buffToJSONObject = function(buffer){
	var obj = {
		value: buffer.toString(DEFAULT_ENCODING),
		encoding: DEFAULT_ENCODING
	};
	return obj;
};

module.exports.jSONObjectToBuffer = function(object){
	var B  = new Buff(object.value, object.encoding);
	return B;
};

module.exports.encryptJSON  = function(jsonBuff, rsaKeys, log){
	var ivBytes = Forge.random.getBytesSync(16);
	var ivBuff = new Buff(Forge.util.bytesToHex(ivBytes), 'hex');

	var aesKeyBytes = Forge.random.getBytesSync(16);

	var aesKeyBuffer = new Buff(Forge.util.bytesToHex(aesKeyBytes), 'hex');

	var cipher = Forge.aes.createEncryptionCipher(aesKeyBytes);
	cipher.start(ivBytes);
	cipher.update(Forge.util.createBuffer(jsonBuff.toString('utf8')));
	cipher.finish();
	var encryptedData = cipher.output;
	var encryptedDataBuff = new Buff(encryptedData.toHex(), 'hex');


	var encrypted = {
		method: 'aes',
		data: module.exports.buffToJSONObject(encryptedDataBuff),
		iv: module.exports.buffToJSONObject(ivBuff),
		keys: {}
	};

	for(var fingerprint in rsaKeys)
	{
		var publicKeyPEMBuffer  = module.exports.jSONObjectToBuffer(rsaKeys[fingerprint]);
		var publicKey = pki.publicKeyFromPem(publicKeyPEMBuffer.toString('utf8'));
		var encodedKeyBytes = publicKey.encrypt(aesKeyBytes);
		var encodedKeyBuffer =  new Buff(Forge.util.bytesToHex(encodedKeyBytes), 'hex');
		encrypted.keys[fingerprint] = module.exports.buffToJSONObject(encodedKeyBuffer);
	}

	return encrypted;
};

module.exports.decryptJSON = function(encrypted, fingerprintHex, privateKeyPEMBuff, log){
	assert.ok(encrypted.data);
	assert.ok(encrypted.method);
	assert.ok(encrypted.iv);
	assert.ok(encrypted.keys);
	assert.ok(fingerprintHex);
	assert.ok(privateKeyPEMBuff);

	var privateKey = pki.privateKeyFromPem(privateKeyPEMBuff.toString('utf8'));

	var encryptedAESKey = encrypted.keys[fingerprintHex];
	assert.ok(encryptedAESKey);
	var encryptedAESKeyBuffer = module.exports.jSONObjectToBuffer(encryptedAESKey);
	var encryptedAESKeyBytes = Forge.util.hexToBytes(encryptedAESKeyBuffer.toString('hex'));
	var decryptedAESKeyBytes = privateKey.decrypt(encryptedAESKeyBytes);
	var decryptedAESKeyBuffer = new Buff(Forge.util.bytesToHex(decryptedAESKeyBytes), 'hex');


	var encryptedDataBuffer = module.exports.jSONObjectToBuffer(encrypted.data);

	var ivBuffer = module.exports.jSONObjectToBuffer(encrypted.iv);
	var ivBytes = Forge.util.hexToBytes(ivBuffer.toString('hex'));

	var encryptedDataBytes = Forge.util.hexToBytes(encryptedDataBuffer.toString('hex'));

	var cipher = Forge.aes.createDecryptionCipher(decryptedAESKeyBytes);
	cipher.start(ivBytes);
	cipher.update(Forge.util.createBuffer(encryptedDataBytes));
	cipher.finish();

	var decryptedHex = cipher.output.toHex();
	var decryptedBuff = new Buff(decryptedHex, 'hex');

	return decryptedBuff;
};

module.exports.createCert = function(name, publicPEMBuffer){
	var fingerprint = module.exports.createPublicKeyPEMFingerprintBuffer(publicPEMBuffer);
	var cert = {
		name: name,
		id: fingerprint.toString('hex'),
		key: module.exports.buffToJSONObject(publicPEMBuffer, 'utf8')
	};
	return cert;
};

module.exports.verifyCertificateChain = function(cert, rootCert, log){
	if (cert.id === rootCert.id)
	{
		log('is root cert, checking fingerprint');
		return module.exports.createPublicKeyPEMFingerprintBuffer(module.exports.jSONObjectToBuffer(cert.key)).toString('hex') === rootCert.id;
	}
	else
	{
		var verified = module.exports.verifyObjectIsSigned(cert, log.wrap('verify cert is signed'));
		if(verified === true)
		{
			if(!cert.signature.signer)
			{
				log('top certificate is not the rootCert');
				return false;
			}
			log('certificate signature check ok, checking further up chain');
			return module.exports.verifyCertificateChain(cert.signature.signer, rootCert, log);
		}
		else
		{
			log('certificate signature check failed');
			return false;
		}
	}
};

