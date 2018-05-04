
"use strict";
var crypto = require('crypto');
exports.passwordDigest = function passwordDigest(nonce, created, password) {
  var pwHash = crypto.createHash('sha1');
  pwHash.update(nonce);
  pwHash.update(created);
  function shaPwd(password) {
    var sha1 = crypto.createHash('sha1');
    sha1.update(password);
    return sha1.digest();
  }
  pwHash.update(shaPwd(password));
  return pwHash.digest('base64');
};


var TNS_PREFIX = '__tns__'; // Prefix for targetNamespace

exports.TNS_PREFIX = TNS_PREFIX;

/**
 * Find a key from an object based on the value
 * @param {Object} Namespace prefix/uri mapping
 * @param {*} nsURI value
 * @returns {String} The matching key
 */
exports.findPrefix = function(xmlnsMapping, nsURI) {
  for (var n in xmlnsMapping) {
    if (n === TNS_PREFIX) continue;
    if (xmlnsMapping[n] === nsURI) {
      return n;
    }
  }
};
