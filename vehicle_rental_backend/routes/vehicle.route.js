const VehicleController = require("../modules/vehicle/vehicle.controller");
const { verifyUser, verifyAuthorization } = require("../middlewares/auth.middlerware");

const router = require("express").Router()
const vehicleController = new VehicleController()

router.post('/', verifyUser, vehicleController.addVehicle)

router.get('/', vehicleController.getVehicles)

router.get('/my-vehicle', verifyUser, vehicleController.getMyVehicles)

router.get('/unverified-vehicle', verifyUser, vehicleController.getUnverifiedVehicles)

router.get('/search', vehicleController.search)

router.get('/:sku', vehicleController.getVehicle)

router.put('/:id', verifyUser, vehicleController.updateVehicle)

router.delete('/:id', verifyUser, vehicleController.deleteVehicle)

router.put('/verify-vehicle/:id', verifyUser, verifyAuthorization, vehicleController.verifyVehicle)


 
module.exports = router