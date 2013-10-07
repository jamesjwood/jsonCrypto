/*jslint node: true */
/*global describe */
/*global it */
/*global before */
/*global after */


var assert = require('assert');
var utils = require('utils');
var events = require('events');

var masterLog = utils.log().wrap('jsonCrypto');

var lib = require('./index.js');
//var crypto = require('crypto');


var EXPONENT = 65537;
var MODULUS = 512;

//seems to fix browserify buffers
var Buff = require('buffer').Buffer;


var privatePEMBase64 = 'LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFcEFJQkFBS0NBUUVBdHYwVVU0M0NBOXJSS3hKQTliZlhGWUNmdHhPODhEZlpWcEFBc2h3bS85R3puWnFVClU4NndVWFBlZUF3ZVUzTTRqenozQnMwQVcrRk1JV3R3cjVnMGxtdDVlbFF1U0dBcmRZYzVGZXdqNURDT1EySmcKcyt5VmI0c1NrZURuSWZ6SE4vSm1hTzg4OG1xRGJ2d2xDZzJheEwvazZxSDVVbi8velVTbGtnZDZMQzJGTGFRdQpFR2FhdUdwRFhTcmZRcnZTS2RqcFNSSEJUS3JNN3JZeU1Pcm02cERmeUFINENTTW5MNDNNODcrSFQ4WmJnUlpqCjhlbXRFbFhMNjJNeXEyVjdEQVlkU2VTMjhaTVFncEFGYjN5b1BYcnRuL3dROWNvbGZmVEpja3REYmhZRUlIZlAKMUQ5bXpjejB4clRUNEx5MVBJV0k1bTJBTTFtNUtmT0QyQUxGVFFJREFRQUJBb0lCQVFDV05NQU9wZnB3ZDVuagpKU1MxanFhN084M2UxaER0anFxVTU3ZnFmRGwzSEllNEF6OW1XKzlYclNrY21iWDdBa1dYTHBBSHdSZGVWRjNOCndRZksyOEd2QjZHN3pJWUJXdy9SZGFKaVlHaEYwNld6b25tR3Q5a2lxcUlmcE9HVmdJMTNXejY5UEVSbktRK2kKZHM5Z3BUSTU5dHJOenc5OXJSd3BQd1E2RG5FMitQRExSRThmZnlLZ000MHlqT1BvQkgwdHljMHF3US9WdEJMRwptQ0VRcTQzMTdvVlJ4Ty9pZ2lNbTRkZGs2cjJXTUNIRE9pbFVOdG1QeFd0bUd6TmRFWjFYbTUrNmJaUVo3aHlmCkJhNXhha3lUQWhpSm41V3BqS2I2TkFjQlJxMmFQUHU1ZHlZbzhGaGZTajI5RXc2T1BpcDRnOTVORkdmMXp3bDAKUVY5cVF3bnhBb0dCQVBQN09DZkhOT21STm1OTXd1K1cvZCtNNHQ4aE5pWVYvUW42WWNjKzIrQ2U5Y0k5TlEyLwpCYkhwYTBUaHBKU1BDQWtiY2wrTUdkRmpnQnA1TGR5SlYvcXJXSGtQaUZBcXlqRkNLYmRqeUM4Q2VrNi9XN3R1CktLenlEZHR3NnhodEpodTJvQXVHdHVvWDFPZjcvMjliQnl3d0Y1aXZvTi9KY2gxWUVRSzdxVTN6QW9HQkFNQUEKc3Bnd2EwTXNQSXhxTTkwNHhQd2poZ0Znd3ZHZVpuUmlna0ZlbkpNTkY5WGY0Q2JOMDZicGZNaTRGRVl0cHg1YgoxbzFYb1U4MlQ0N3dLelB4OG13alJHYWZFWGZhWmlvRDRIYTFZTmdKZGdMR0YxTVJwRDlhSms5aHJ5RkZ3VU5aCnRPV09iaDRiOXVKS1M2ZmNpdk53MDhmUlN1RkdKSm1UdmROaGxpKy9Bb0dBSlppNXo0OW4vUElPa29DNnJWYjAKS2lXNHRDK1crNGw1NDdhOHFJcHNNWkh0UnhCTmc1L0REZVp0VEVFRkxvdFg3cWRYR1pncVJsVHg0YUo0eWJvMApYNEZWOGRuTjVLU2pZYkhUWWRvemQrTUcyK21yQmhmMGxxbjZMcTJZM0x1OUdwb3EwWHZoNWZMa01SZHBCa3pkCnJ4WitIRjQ4Q1NBdXdJelltalkyNGJjQ2dZRUFsZTYxaUNTZlRqZzRIQW8rNyt5SjNyODZ3TTYzeklnK1IzbzUKYnlTYnJqVldQSnh6Wkxuc0luWklERkc2KzBaaEwxTFdDMCszMXF4NW1nd3dJSU02SkhteHkxVkNCYzdWWXMvZQpNN1RWcUQ1VEdqMW9MMlVpVnBwbU9pejAzazJqYXAyZHBuai93cUZodkRuNk5GNERYN0Rtb0MzdWhGWUs5S2FyCllHcmZKZThDZ1lCcUd6TkV3Y2ZGMFVIaVVDaGEyVFdXMnl6cG1VaUxTRXZtNUJ3cUc5MjVYL2xyM1UrUEtweEgKYVM0SXlPYUNJN01TR28zSnEvVEhhREhCbzl5ZWpHNzF2bFc5QVpsNGFhSGp1NENtSnljeks0WW51MUIzV250RgpybnpodkJybFM1eDIvbEJ2UjF3NE85VHZNWGRlRjZXM3lmelRNS0ZReTEyaS96NjhNY3dYMlE9PQotLS0tLUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo=';
var publicPEMBase64 = 'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF0djBVVTQzQ0E5clJLeEpBOWJmWApGWUNmdHhPODhEZlpWcEFBc2h3bS85R3puWnFVVTg2d1VYUGVlQXdlVTNNNGp6ejNCczBBVytGTUlXdHdyNWcwCmxtdDVlbFF1U0dBcmRZYzVGZXdqNURDT1EySmdzK3lWYjRzU2tlRG5JZnpITi9KbWFPODg4bXFEYnZ3bENnMmEKeEwvazZxSDVVbi8velVTbGtnZDZMQzJGTGFRdUVHYWF1R3BEWFNyZlFydlNLZGpwU1JIQlRLck03cll5TU9ybQo2cERmeUFINENTTW5MNDNNODcrSFQ4WmJnUlpqOGVtdEVsWEw2Mk15cTJWN0RBWWRTZVMyOFpNUWdwQUZiM3lvClBYcnRuL3dROWNvbGZmVEpja3REYmhZRUlIZlAxRDltemN6MHhyVFQ0THkxUElXSTVtMkFNMW01S2ZPRDJBTEYKVFFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==';

var privatePEMBuffer = new Buff(privatePEMBase64, 'base64');
var publicPEMBuffer= new Buff(publicPEMBase64, 'base64');

var privatePEMString = privatePEMBuffer.toString('utf8');
var publicPEMString= publicPEMBuffer.toString('utf8');


var rootPair = lib.generateKeyPEMBufferPair(MODULUS, EXPONENT);
var rootPrivatePEMBuffer = rootPair.privatePEM;
var rootCert = lib.createCert(rootPair.publicPEM);



describe('jsonCrypto', function () {
    'use strict';
    it('1: should be able to gererate a key pair', function (done) {
        var log = masterLog.wrap('1');
        var pair = lib.generateKeyPEMBufferPair(MODULUS, EXPONENT);
        assert.ok(pair);
        assert.ok(pair.publicPEM);
        assert.ok(pair.privatePEM);

        done();
    });


    it('3: should be able to hash SHA256', function (done) {
        var log = masterLog.wrap('3');
        var myObject = {_id: 'hello'};

        var myString = JSON.stringify(myObject);
        var objectBuff = new Buff(myString, 'utf8');
        var hash = lib.hashBuffer(objectBuff,'sha256', log);

        //var standardHasher = crypto.createHash('sha256');
        //var buf = new Buff(myString, 'utf8');
        //standardHasher.update(buf, 'utf8');
        var standardHash = "HvUiAt8PyOHYCz8u2huO/MoNWAqn9/HnENoUEi8aHWo=";
        assert.equal(standardHash, hash.toString('base64'));
        done();

    });

    it('4: should be able to hash MD5', function (done) {
        var log = masterLog.wrap('4');
        var myObject = {_id: 'hello'};

        var myString = JSON.stringify(myObject);
        var objectBuff = new Buff(myString, 'utf8');
        var hash = lib.hashBuffer(objectBuff,'md5', log);

        ///var standardHasher = crypto.createHash('md5');
        //var buf = new Buff(myString, 'utf8');
        //standardHasher.update(buf, 'utf8');
        var standardHash = 'RyMjqV96Q6c0xaGmEriEVg==';


        assert.equal(standardHash,  hash.toString('base64'));
        done();
    });


    it('5: should be able to sign', function () {
        var log = masterLog.wrap('5');
        var myObject = {message: 'hello'};
        log('signing object');

        var cert = lib.createCert(publicPEMBuffer);
        var signed = lib.signObject(myObject, privatePEMString, cert, true, log.wrap('sign'));

        var sig = "Q4U3Q8B0qHW1J304lEGVFDph6E8QvOlrAvr552eSQGSBvL6YybpdSEUn9XjqhGiF5LgrIRMAzDz+rZ3lZIYzc5QujJfMWBg0kHh47tJ8lNn+KNvk0CDIt2+AW1CvTPZCoDz7K1hnB9gtIFx6h7RkAZNo+1QXwX2mASnwVI9sORmYi0vhfddezlRlz/aVGvBNQcrKNlQWPdef5/qbyNyjU+tDs3UhpnWnKW9zbFSxdl+C33UNbz2qt4jE9wY02wPQofJ4KPCv4eHVPVcLgMURMNwc6IjUNPzhAXjuaD6Sy54Ns5NOpg57FyiBHSOwla7htZ8h64lZ/q8jvVIOHWrODg==";
        log(sig);
        log(signed.signature.signed);
        assert.equal(sig, signed.signature.signed.value);
    });


    it('6: should be able to verify', function (done) {
        var log = masterLog.wrap('6');
        var myObject = {message: 'hello'};

        var cert = lib.createCert(publicPEMBuffer);
        var signedCert = lib.signObject(cert, rootPrivatePEMBuffer, rootCert, true, log.wrap('siging cert with rootCert'));


        var signed = lib.signObject(myObject, privatePEMBuffer, signedCert, true, log.wrap('signing'));


        //var b = new Buff(JSON.stringify(myObject), 'utf8');
        //var verify = publicPEM.hashAndVerify('sha256',b, signed.signature.signature, 'base64');
        //if(!verify)
        //{
        //    throw new Error('could not verify');
        //}
        //log('verified ok with openSSL');
        var verified = lib.verifyObject(signed, log.wrap('verifying'));
        assert.equal(lib.verifyObject.SIGNATURE_VALID, verified);
        done();
    });

    it('7: _rev should not be hashed and signed', function () {
        var log = masterLog.wrap('7');
        var myObject = {message: 'hello', _rev: 'myid'};
        log('signing object');
        var cert = lib.createCert(publicPEMBuffer);
        var signed = lib.signObject(myObject, privatePEMBuffer, cert, true, log.wrap('sign'));

        var sig = "Q4U3Q8B0qHW1J304lEGVFDph6E8QvOlrAvr552eSQGSBvL6YybpdSEUn9XjqhGiF5LgrIRMAzDz+rZ3lZIYzc5QujJfMWBg0kHh47tJ8lNn+KNvk0CDIt2+AW1CvTPZCoDz7K1hnB9gtIFx6h7RkAZNo+1QXwX2mASnwVI9sORmYi0vhfddezlRlz/aVGvBNQcrKNlQWPdef5/qbyNyjU+tDs3UhpnWnKW9zbFSxdl+C33UNbz2qt4jE9wY02wPQofJ4KPCv4eHVPVcLgMURMNwc6IjUNPzhAXjuaD6Sy54Ns5NOpg57FyiBHSOwla7htZ8h64lZ/q8jvVIOHWrODg==";
        log(sig);
        log(signed.signature.signed);
        assert.equal(sig, signed.signature.signed.value);
    });



    it('8: should be able to encryptValue, decryptValue', function (done) {
        var log = masterLog.wrap('8');
        var secret = "secret";
        var secretBuffer = new Buff(secret);
        var propertiesToEncrypt = ['toBeEncrypted'];

        var fingerprintBuffer = lib.createPublicKeyPEMFingerprintBuffer(publicPEMBuffer);
        var keys = {};
        var fingerprint = fingerprintBuffer.toString('hex');
        keys[fingerprint] = lib.buffToJSONObject(publicPEMBuffer);

        var encrypted = lib.encryptJSON(secretBuffer, keys, log.wrap('encryptValue'));

        assert.ok(encrypted.keys[fingerprint]);
        assert.ok(encrypted.data);
        assert.ok(encrypted.method);
        assert.ok(encrypted.iv);

        log.dir(encrypted);


        var decryptedBuffer = lib.decryptJSON(encrypted, fingerprint,  privatePEMBuffer, log.wrap('decryptValue'));

        assert.equal(secret, decryptedBuffer.toString('utf8'));
        done();
    });

    it('9: should be able to encrypt, decrypt', function (done) {

        var log = masterLog.wrap('9');
        var unencrypted = {message: 'hello', _id: 'myid', secret1:'hello secret1', secret2: 23213123123, secret3: null};


        var fingerprintBuffer = lib.createPublicKeyPEMFingerprintBuffer(publicPEMBuffer);
        var keys = {};
        var fingerprint = fingerprintBuffer.toString('hex');
        keys[fingerprint] = lib.buffToJSONObject(publicPEMBuffer);


        var encrypted = lib.encrypt(unencrypted, ['secret1', 'secret2', 'secret3'], keys, log.wrap('encrypt'));

        assert.equal(encrypted.message, unencrypted.message);
        assert.equal(encrypted._id, unencrypted._id);

        log.dir(encrypted);
        var decrypted = lib.decrypt(encrypted, ['secret1', 'secret2', 'secret3'], fingerprint, privatePEMBuffer, log.wrap('encrypt'));

        assert.equal(decrypted.secret1, unencrypted.secret1);
        assert.equal(decrypted.secret2, unencrypted.secret2);
        assert.equal(decrypted.message, unencrypted.message);
        assert.equal(decrypted._id, unencrypted._id);
        log.dir(decrypted);

        done();

    });
     it('10: should be able to sign and verify with generated keys', function (done) {
        var log = masterLog.wrap('10');
        var myObject = {message: 'hello'};
        var pair = lib.generateKeyPEMBufferPair(MODULUS, EXPONENT);
        log('signing object');

        var cert = lib.createCert(publicPEMBuffer);
        var signedCert = lib.signObject(cert, rootPrivatePEMBuffer, rootCert,  true,log.wrap('siging cert with rootCert'));


        var signed = lib.signObject(myObject, privatePEMBuffer, signedCert,  true, log.wrap('signing'));
        var verified = lib.verifyObject(signed, log.wrap('verifying'));
        assert.equal(lib.verifyObject.SIGNATURE_VALID, verified, 'should return true');
        done();
    });

    it('12: should verify untrusted but signed objects', function (done) {
        var log = masterLog.wrap('12');
        var myObject = {message: 'hello'};
        var pair = lib.generateKeyPEMBufferPair(MODULUS, EXPONENT);
        log('signing object');

        var cert = lib.createCert(publicPEMBuffer);


        var signed = lib.signObject(myObject, privatePEMBuffer, cert, true, log.wrap('signing'));
        var verified = lib.verifyObject(signed, log.wrap('verifying'));
        assert.equal(lib.verifyObject.SIGNATURE_VALID, verified);
        done();
    });
    it('13: should add and validate proof of work', function (done) {
        var log = masterLog.wrap('13');
        var myObject = {message: 'hello'};
        var before = new Date();
        var newObject = lib.addProofOfWork(myObject, {precision: 4});
        var after = new Date();
        var time = (after - before)/1000;
        log(time + ' milliseconds to do work');
        var valid = lib.validateProofOfWork(newObject);
        log('value was ' + newObject.proofOfWork.value);
        assert.ok(valid);
        done();
    });
});