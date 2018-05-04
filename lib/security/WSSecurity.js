"use strict";

var crypto = require('crypto');
var passwordDigest = require('../utils').passwordDigest;
var validPasswordTypes = ['PasswordDigest', 'PasswordText'];
var uuidV4 = require('uuid/v4');
var Buffer = require('buffer').Buffer;

function WSSecurity(username, password, options) {
  options = options || {};
  this._username = username;
  this._password = password;
  //must account for backward compatibility for passwordType String param as well as object options defaults: passwordType = 'PasswordText', hasTimeStamp = true
  if (typeof options === 'string') {
    this._passwordType = options ? options : 'PasswordText';
    options = {};
  } else {
    this._passwordType = options.passwordType ? options.passwordType : 'PasswordText';
  }

  if (validPasswordTypes.indexOf(this._passwordType) === -1) {
    this._passwordType = 'PasswordText';
  }

  this._hasTimeStamp = options.hasTimeStamp || typeof options.hasTimeStamp === 'boolean' ? !!options.hasTimeStamp : true;
  /*jshint eqnull:true */
  if (options.hasNonce != null) {
    this._hasNonce = !!options.hasNonce;
  }
  this._hasTokenCreated = options.hasTokenCreated || typeof options.hasTokenCreated === 'boolean' ? !!options.hasTokenCreated : true;
  if (options.actor != null) {
    this._actor = options.actor;
  }
  if (options.mustUnderstand != null) {
    this._mustUnderstand = !!options.mustUnderstand;
  }
}

WSSecurity.prototype.toXML = function() {
  // avoid dependency on date formatting libraries
  function getDate(d) {
    function pad(n) {
      return n < 10 ? '0' + n : n;
    }
    return d.getUTCFullYear() + '-'
      + pad(d.getUTCMonth() + 1) + '-'
      + pad(d.getUTCDate()) + 'T'
      + pad(d.getUTCHours()) + ':'
      + pad(d.getUTCMinutes()) + ':'
      + pad(d.getUTCSeconds()) + 'Z';
  }
  var now = new Date();
  var created = getDate(now);
  var timeStampXml = '';
  if (this._hasTimeStamp) {
    var expires = getDate( new Date(now.getTime() + (1000 * 600)) );
    timeStampXml = "<wsu:Timestamp wsu:Id=\"Timestamp-"+created+"\">" +
      "<wsu:Created>"+created+"</wsu:Created>" +
      "<wsu:Expires>"+expires+"</wsu:Expires>" +
      "</wsu:Timestamp>";
  }

  var password, nonce, base64nonce;
  if (this._hasNonce || this._passwordType !== 'PasswordText') {
   // base64nonce = new Buffer(created +  Math.random()).toString('base64');
  
   var nHash = crypto.createHash('sha1');
   nHash.update(created + Math.random());
   nonce =  nHash.digest().toString().substr(0, 16);
   base64nonce = new Buffer(nonce).toString('base64');
  
   //console.log(nonce)
  }
  if (this._passwordType === 'PasswordText') {
    password = "<wsse:Password Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText\">" + this._password + "</wsse:Password>";
    if (nonce) {
      password += "<wsse:Nonce EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\">" + nonce + "</wsse:Nonce>";
    }
  } else {
    password = "<wsse:Password Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest\">" + passwordDigest(nonce, created, this._password) + "</wsse:Password>" +
      "<wsse:Nonce EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\">" + base64nonce + "</wsse:Nonce>";
  }
  var messageId = uuidV4().toUpperCase();
  var message = '<ns2:MessageID xmlns:ns2="http://www.w3.org/2005/08/addressing">'+ messageId +'</ns2:MessageID>'+
  '<ns2:Action xmlns:ns2="http://www.w3.org/2005/08/addressing">http://webservices.amadeus.com/FMPCAQ_16_3_1A</ns2:Action>'+
  '<ns2:To xmlns:ns2="http://www.w3.org/2005/08/addressing">https://nodeD2.test.webservices.amadeus.com/1ASIWIHAIHA</ns2:To>';

  return message + "<wsse:Security " + (this._actor ? "soap:actor=\"" + this._actor + "\" " : "") +
    (this._mustUnderstand ? "soap:mustUnderstand=\"1\" " : "") +
    "xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">" +
    "<wsse:UsernameToken xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" wsu:Id=\"SecurityToken-" + created + "\">" +
    "<wsse:Username>" + this._username + "</wsse:Username>" +
    password +
    (this._hasTokenCreated ? "<wsu:Created>" + created + "</wsu:Created>" : "") +
    "</wsse:UsernameToken>" +
    "</wsse:Security>" +
    '<ns4:AMA_SecurityHostedUser xmlns:ns4="http://xml.amadeus.com/2010/06/Security_v1"><ns4:UserID xmlns:ns4="http://xml.amadeus.com/2010/06/Security_v1" POS_Type="1" PseudoCityCode="YVRC4210G" AgentDutyCode="SU" RequestorType="U"/></ns4:AMA_SecurityHostedUser>'
};

module.exports = WSSecurity;
