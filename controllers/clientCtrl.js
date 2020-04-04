'use strict';
const controllerCtrl = {};

const rsa = require('rsa');
const bc = require('bigint-conversion');
const sha = require('object-sha');
var CryptoJS = require('node-cryptojs-aes').CryptoJS;
const crypto = require("crypto");




let keyPair;

let Po;

let k;

let iv;

let aPubKey;

let cryptotext
controllerCtrl.getData = async (req, res) => {
  try {
    keyPair = await rsa.generateRandomKeys();
    res.status(200).send({
      e: bc.bigintToHex(keyPair["publicKey"]["e"]),
      n: bc.bigintToHex(keyPair["publicKey"]["n"])
    })
  } catch (err) {
    res.status(500).send({ message: err })
  }
}

controllerCtrl.postData = async (req, res) => {
  try {
    const c = req.body.msg;
    const m = await keyPair["privateKey"].decrypt(bc.hexToBigint(c));
    res.status(200).send({ msg: bc.bigintToHex(m) })
  } catch (err) {
    res.status(500).send({ message: err })
  }
}

controllerCtrl.signMessage = async (req, res) => {
  console.log("Sign");
  console.log(req.body);
  try {
    const m = bc.hexToBigint(req.body.msg);
    const s = await keyPair["privateKey"].sign(m);
    res.status(200).send({ msg: bc.bigintToHex(s) })
  } catch (err) {
    res.status(500).send({ message: err })
  }
}

controllerCtrl.noRepudioMessage = async (req, res) => {
  console.log("No repudation");
  console.log(req.body);
  cryptotext = req.body.body.msg;
  Po = req.body.signature;
  aPubKey = new rsa.PublicKey(bc.hexToBigint(req.body.pubKey.e), bc.hexToBigint(req.body.pubKey.n));
  let proofDigest = bc.bigintToHex(await aPubKey.verify(bc.hexToBigint(req.body.signature)));
  let bodyDigest = await sha.digest(req.body.body);
  // Comprovar timestamp
  console.log("Timestamp");
  var tsB = new Date();
  var tsA = req.body.body.timestamp;
  tsA = new Date(tsA);
  var seconds = (tsB.getTime() - tsA.getTime()) / 1000;
  console.log(seconds);
  if ((bodyDigest === proofDigest) && (seconds < 1)) {
    try {
      const m = bc.hexToBigint(req.body.body.msg);
      const body = {
        type: "2",
        src: "A",
        dest: "B",
        msg: bc.bigintToText(m),
        timestamp: tsB
      };
      const digest = await sha.digest(body, 'SHA-256');
      const digestHex = bc.hexToBigint(digest);
      const signature = await keyPair["privateKey"].sign(digestHex);
      res.status(200).send({
        body: body,
        signature: bc.bigintToHex(signature)
      })
    } catch (err) {
      res.status(500).send({ message: err })
    }
  }
  else { console.log("Pruebas malamente"); }
}

function getK() {
  console.log("getK");
  require('request')('http://localhost:3001/api/clientes/downloadK', (err, res, body) => {
    console.log(body);
    const bod = body.split("-");
    k = bod[0];
    iv = bod[1];
    decrypt(k, iv);
  });
}


controllerCtrl.advertB = async (req, res) => {
  console.log("Advert");
  console.log(req.body);
  getK();
}


function decrypt(key, iv) {
  console.log(iv);
  console.log(key);
  console.log(cryptotext);
  let key2 = bc.hexToBuf(key);
  let iv2 = bc.hexToBuf(iv);

 let encryptedText = Buffer.from(cryptotext, 'hex');
 let decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key2), iv2);
 let decrypted = decipher.update(encryptedText);
 decrypted = Buffer.concat([decrypted, decipher.final()]);
 console.log(decrypted.toString());
}


module.exports = controllerCtrl;