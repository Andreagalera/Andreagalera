'use strict';
const controllerCtrl = {};

const rsa = require('rsa');
const bc = require('bigint-conversion');
const sha = require('object-sha');

let keyPair;

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
    const m = bc.hexToBigint(req.body.body.msg);
    const s = await keyPair["privateKey"].sign(m);
    var ts = new Date();
    const body = {
      type: "2",
      src: "B",
      dest: "A",
      msg: bc.bigintToHex(s),
      timestamp: ts
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



module.exports = controllerCtrl;