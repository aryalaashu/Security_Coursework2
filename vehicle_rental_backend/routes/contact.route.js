const ContactContrller = require("../modules/contacts/contact.controlle");
const { verifyUser, verifyAuthorization,verifyRecaptcha } = require("../middlewares/auth.middlerware");

const router = require("express").Router()
const contactContrller = new ContactContrller()

router.post('/', verifyRecaptcha,contactContrller.addContact)

router.get('/', verifyUser, verifyAuthorization, contactContrller.getContact)


module.exports = router