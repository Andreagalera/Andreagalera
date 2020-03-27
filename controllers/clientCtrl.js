'use strict';
const controllerCtrl = {};

const rsa = require('rsa');
const bc = require('bigint-conversion');

let keyPair;

controllerCtrl.getData = async (req, res) => {
  try {
    keyPair = await rsa.generateRandomKeys();
    res.status(200).send({
      e: bc.bigintToHex(keyPair["publicKey"]["e"]),
      n: bc.bigintToHex(keyPair["publicKey"]["n"])
    })
  }catch(err) {
    res.status(500).send ({ message: err})
  }
}

controllerCtrl.postData =  async (req, res) => {
  try {
    const c = req.body.msg;
    const m = await keyPair["privateKey"].decrypt(bc.hexToBigint(c));
    res.status(200).send({msg: bc.bigintToHex(m)})
  }catch(err) {
    res.status(500).send ({ message: err})
  }
}

controllerCtrl.signMessage =  async (req, res) => {
  try {
    const m = bc.hexToBigint(req.body.msg);
    const s = await keyPair["privateKey"].sign(m);
    res.status(200).send({msg: bc.bigintToHex(s)})
  }catch(err) {
    res.status(500).send ({ message: err})
  }
}



module.exports = controllerCtrl;