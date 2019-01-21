'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});
exports['default'] = encryptWithPublicKey;

var _eccrypto = require('eccrypto');

var _publicKey = require('./public-key');

function encryptWithPublicKey(publicKey, message) {

    // ensure its an uncompressed publicKey
    publicKey = (0, _publicKey.decompress)(publicKey);

    // re-add the compression-flag
    var pubString = '04' + publicKey;

    const opts = {
        ephemPrivateKey:new Buffer("fca39e05a26cde57a09a4ba891afe252707758acd8b332f6fad4c20327bc70b6",'hex'),
        iv: new Buffer("d100f13bf818aa7441ecc7edb34ebcb4",'hex')
    }

    return (0, _eccrypto.encrypt)(new Buffer(pubString, 'hex'), Buffer(message),opts).then(function (encryptedBuffers) {
        var encrypted = {
            iv: encryptedBuffers.iv.toString('hex'),
            ephemPublicKey: encryptedBuffers.ephemPublicKey.toString('hex'),
            ciphertext: encryptedBuffers.ciphertext.toString('hex'),
            mac: encryptedBuffers.mac.toString('hex')
        };
        return encrypted;
    });
}