const { Router} = require('express');
const router = Router();


const controller = require('../controllers/clientCtrl');

// router.get('/', controller.getData);
// router.post('/', controller.postData);
// router.put('/', controller.putData);
// router.delete('/', controller.deleteData);

router.get('/', controller.getData);
router.post('/', controller.postData);
router.post('/sign', controller.signMessage);


module.exports = router;