import axios from '../../axios'
import React, { useContext, useEffect, useState } from 'react'
import toast from 'react-hot-toast'
import { BiEdit, BiLoader, BiSolidStar, BiStar } from 'react-icons/bi'
import { CiCircleCheck } from 'react-icons/ci'
import Rating from 'react-rating'
import { useParams } from 'react-router-dom'
import { AuthContext } from '../../context/authContext';
import { Field, Form, Formik } from 'formik'
import { loadStripe } from '@stripe/stripe-js'
import Modal from 'react-modal'
import dayjs from 'dayjs'
import EditBookingModal from './EditBookingModal'
import ReCAPTCHA from 'react-google-recaptcha';

function SingleVehicle() {
    const [isLoading, setIsLoading] = useState(false)

    const { sku } = useParams()
    const { isAuthenticated, userDetails } = useContext(AuthContext)
    const [selectedImage, setSelectedImage] = useState();

    console.log('userDetails', userDetails?._id)

    const [isAgree, setIsAgree] = useState(false);
    const [rating, setRating] = useState(0);

    const [isVehicleOwned, setIsVehicleOwned] = useState(false);
    const [vehicleData, setVehicleData] = useState()
    const [modalIsOpen, setModalIsOpen] = useState(false)

    const [openEditModal, setOpenEditModal] = useState(false)

    const [reviewList, setReviewList] = useState([])

    const [selectedVehicleData, setSelectedVehicleData] = useState()

    const [packageList, setPackageList] = useState()
    const [recaptcha, setRecaptcha] = useState(null);


    const getMyBookings = async () => {
        try {
            let result = await axios.get("/booking/my-booking", {
                params: {
                    page: 1,
                    size: 9999,
                },
            });

            if (result.data.success) {

                const data = result.data.data.find((value) => (
                    value.vehicle.sku === sku
                ))

                setSelectedVehicleData(data)
                if (data) setIsVehicleOwned(true)
            } else toast.error("Failed");
        } catch (ERR) {
            console.log(ERR);
            toast.error(ERR.response.data.msg);
        }
    }

    useEffect(() => {
        if (isAuthenticated) {
            getMyBookings()
        }

    }, [])

    const closeModal = () => {
        setModalIsOpen(false)
        setPackageList(undefined)
    }

    const includedInPrice = [
        "Air Conditioning",
        "Fuel Policy",
        "Meet And Greet"
    ]

    const getVehicleDetails = async () => {
        try {
            let result = await axios.get('/vehicle/' + sku)

            if (result.data.success) {
                setVehicleData(result.data.data)
                setSelectedImage(result.data.data.images[0])
                getReview(result.data.data._id)
            } else toast.error('Failed')
        } catch (ERR) {
            console.log(ERR)
            toast.error(ERR.response.data.msg)
        }
    }

    const scrollToTop = () => {
        window.scrollTo({
            top: 0,
            behavior: "smooth", // for smoothly scrolling
        });
    };

    useEffect(() => {
        getVehicleDetails()
        scrollToTop()
    }, [])

    const makePayment = async (value, type) => {
        try {

            setIsLoading(true)
            const stripe = await loadStripe(process.env.REACT_APP_STRIPE_PL)

            let totalDays = 0

            const pickupDate = value?.pickup_date ? new Date(value.pickup_date) : null;
            const dropDate = value?.drop_date ? new Date(value.drop_date) : null;

            if (pickupDate && dropDate && !isNaN(pickupDate) && !isNaN(dropDate)) {
                const timeDifference = dropDate - pickupDate;
                const dayDifference = timeDifference / (1000 * 60 * 60 * 24);
                totalDays = (Math.ceil(dayDifference) + 1);
            } else {
                console.log("Invalid dates");
            }
            const token = await recaptcha.executeAsync();

            const body = {
                vehicle: vehicleData?._id,
                price: vehicleData?.price * totalDays,
                pickup_date: value?.pickup_date,
                drop_date: value?.drop_date,
                address: value?.address,
                contact: value?.contact,
                recaptchaToken: token
            }

            const response = await axios.post(`${process.env.REACT_APP_BASE_URI}booking/create-intent`, body)

            // const result = stripe.redirectToCheckout({
            //     vehicleId: response.data.id
            // })
            if (response.data.url) {
                window.location.href = response.data.url
            }

            // if ((await result).error) {
            //     setTimeout(() => {
            //         setIsLoading(false)
            //     }, 500)
            //     console.log((await result).error)
            // }
        } catch (error) {
            setTimeout(() => {
                setIsLoading(false)
                toast.error(error.response.data.msg)
            }, 500)
            console.log(error)
        }
    }

    const addReview = async (values, actions) => {
        try {
            let result = await axios.post('/review/', {
                ...values,
                vehicle: selectedVehicleData.vehicle._id,
                rating: rating
            })

            if (result.data.success) {
                toast.success(result.data.msg)
                setRating(0)
                actions.resetForm()
                getVehicleDetails()
            } else toast.error(result.data.msg || 'Failed')
        } catch (ERR) {
            toast.error('Failed')
        }
    }

    const getReview = async (id) => {
        try {
            let result = await axios.get('/review/' + id)

            if (result.data.success) {
                setReviewList(result.data.data)
            } else toast.error(result.data.msg || 'Failed')
        } catch (ERR) {
            toast.error('Failed')
        }
    }

    const closeEditBookingModal = () => {
        setOpenEditModal(false)
    }


    const getRouteAfterEdit = () => {
        getVehicleDetails()
        getMyBookings()
    }

    return (
        <div className="md:flex items-start justify-center py-12 2xl:px-20 md:px-6 px-4 container mx-auto">
            {
                isLoading &&
                <div className='fixed h-screen top-0 w-full bg-black bg-opacity-65 z-[999999] grid place-items-center'>
                    <label className='flex items-center gap-3 font-semibold text-white'><BiLoader className='animate-spin' /> Loading... </label>
                </div>
            }

            {
                openEditModal &&
                <EditBookingModal
                    closeModal={closeEditBookingModal}
                    getRoute={getRouteAfterEdit}
                    modalIsOpen={openEditModal}
                    data={selectedVehicleData}
                />
            }

            <Modal
                ariaHideApp={false}
                isOpen={modalIsOpen}
                onRequestClose={closeModal}
                contentLabel="Choose Option"
                overlayClassName="Overlay"
                className="Modal rounded-md p-10 max-w-xl max-h-screen overflow-auto"
            >

                <div>
                    <h2 className='text-xl uppercase text-center mt-5 font-semibold opacity-70'>{vehicleData?.name}</h2>
                    <p className='font-semibold text-center mb-10 mt-2'>Fill the Details below to book the vehicle</p>
                </div>

                <div className='grid gap-2 mt-4'>

                    <Formik
                        enableReinitialize
                        initialValues={{
                            // name: "",
                            pickup_date: "",
                            drop_date: "",
                            address: "",
                            contact: ""
                        }}
                        onSubmit={(values, actions) => {
                            makePayment(values, actions);
                        }}
                        className='mt-10'>
                        {(props) => (
                            <Form >
                                <div className='grid grid-cols-2 gap-3'>
                                    {/* <div className='col-span-full'>
                                        <label>Name</label>
                                        <Field name="name" className='inputfield mt-2' />
                                    </div> */}
                                    <div className=''>
                                        <label>Pick Date</label>
                                        <Field name="pickup_date" className='inputfield mt-2' type="date" min={dayjs().format('YYYY-MM-DD')} />
                                    </div>
                                    <div className=''>
                                        <label>Drop Date</label>
                                        <Field name="drop_date" className='inputfield mt-2' type="date" min={props.values.pickup_date} />
                                    </div>
                                    <div className='col-span-full'>
                                        <label>Address</label>
                                        <Field name="address" className='inputfield mt-2' />
                                    </div>
                                    <div className='col-span-full'>
                                        <label>Contact</label>
                                        <Field name="contact" className='inputfield mt-2' type="string" />
                                    </div>

                                    <div className='col-span-full my-5'>
                                        <label className='flex gap-3'>
                                            <input type='checkbox' checked={isAgree} onChange={(e) => {
                                                setIsAgree(e.target.checked)
                                            }} />
                                            Note: If changes in pick up and drop dates needs to be done, you should contact the admin before 24 hrs.
                                        </label>
                                    </div>
                                </div>
                                                
                                <div className="mt-6  w-full">
                                    <ReCAPTCHA
                                    sitekey="6Ld5_CoqAAAAAOy3WS3NLMssRnPHABtCvw9NYJpX"  // Replace with your reCAPTCHA v3 Site Key
                                    size="invisible"
                                    ref={(el) => setRecaptcha(el)}
                                    />
                                </div>
                                <button className='btn-primary w-full' type='submit' disabled={!isAgree}>
                                    Submit
                                </button>
                            </Form>
                        )}

                    </Formik>
                </div>
            </Modal>


            <div className="md:w-1/2">
                <img className="w-full md:h-96 h-72 object-contain" alt={vehicleData?.name} src={`${process.env.REACT_APP_IMG_URI}${selectedImage}`} />
                <div className="flex items-center  mt-3 space-x-4 md:space-x-2 overflow-x-auto">
                    {vehicleData?.images && vehicleData?.images.map((img, index) => (
                        <img key={index} onClick={() => {
                            setSelectedImage(img)
                        }} alt={vehicleData?.name} className={`md:w-48 md:h-48 h-20 w-full object-contain border-2 ${selectedImage === img ? "border-blue-600 shadow" : "border-gray-200"}`} src={`${process.env.REACT_APP_IMG_URI}${img}`} />
                    ))}
                </div>

                {
                    isVehicleOwned &&
                    <Formik
                        enableReinitialize
                        initialValues={{
                            message: ""
                        }}
                        onSubmit={(values, actions) => {
                            addReview(values, actions);
                        }}
                        className='mt-10'>
                        {(props) => (
                            <Form >
                                <h2 className='font-semibold text-lg mt-10'>Add a Review</h2>
                                <p className='my-3 mb-10'>Your email address will not be published. Required fields are marked <b className='text-red-600'>*</b></p>

                                <div className='my-3'>
                                    <Rating onChange={(value) => {
                                        setRating(value)
                                    }}
                                        initialRating={rating}

                                        fullSymbol={<BiSolidStar size={20} fill='#FFA128' />} emptySymbol={<BiStar size={20} fill='#FFA128' />} />
                                </div>

                                <div className='grid grid-cols-2 gap-3'>
                                    <div className='col-span-full'>
                                        <label>Your Review <b className='text-red-600'>*</b></label>
                                        <Field required as="textarea" name="message" className='inputfield mt-2' />
                                    </div>

                                    <button className='btn-primary' type='submit'>
                                        Submit
                                    </button>
                                </div>
                            </Form>
                        )}

                    </Formik>
                }
                <div className='mt-10 border-t pt-5'>

                    {
                        reviewList.length > 0 ?
                            <p className='text-center font-semibold text-xl'>Latest Reviews</p>
                            :
                            <p className='text-center font-semibold text-xl text-gray-300'>No Reviews Available</p>
                    }

                    {
                        reviewList.map((review, index) => (
                            <div key={index} className=" text-base bg-white rounded-lg mb-10 mt-5 ">
                                <div className="flex justify-between items-center mb-2">
                                    <div className="flex items-center">
                                        <p className="inline-flex items-center mr-3 text-sm text-gray-900  font-semibold">
                                            {/* <img
                                                className="mr-2 w-6 h-6 rounded-full"
                                                src={`${process.env.REACT_APP_IMG_URI}${review.user.image}`}
                                                alt="Michael Gough" /> */}
                                            {review.user.firstname} {review.user.lastname}
                                        </p>
                                    </div>
                                </div>
                                <p className="text-sm text-gray-600 mb-4"> {dayjs(review.updatedAt).format('MMM DD, YYYY')} </p>
                                <p className="text-gray-500 ">{review.message}</p>
                            </div>
                        ))
                    }
                </div>
            </div>

            <div className=" md:w-1/2 lg:ml-8 md:ml-6 md:mt-0 mt-6">
                <Rating initialRating={vehicleData?.rating} step={1} readonly fullSymbol={<BiSolidStar size={20} fill='#FFA128' />} emptySymbol={<BiStar size={20} fill='#FFA128' />} />

                <div className="border-b border-gray-200 pb-6">
                    <h1
                        className="
                        lg:text-2xl
                        text-xl
                        font-semibold
                        lg:leading-6
                        leading-7
                        text-gray-800
                        mt-2
                        capitalize
                        "
                    >
                        {vehicleData?.name}
                    </h1>
                    <p className=" leading-none text-gray-600 mt-4">Rs. {vehicleData?.price}/Day</p>
                </div>
                <div className="border-b border-gray-200 py-6">
                    <p className=" text-gray-600">{vehicleData?.description}</p>

                </div>
                <div className="border-b border-gray-200 py-6">
                    <p className="text-lg leading-none font-semibold">Key Feature</p>

                    <div className='grid xl:grid-cols-3 lg:grid-cols-2 md:grid-cols-1 sm:grid-cols-2 grid-cols-2 justify-center gap-8 mt-10 mb-3 '>
                        <div className='flex items-center  gap-2'>
                            <div className='h-10 w-10 grid place-items-center p-2 rounded-full bg-gray-200'>
                                <img className='h-4 ' src='/seat.png' />
                            </div>
                            <div className='text-sm'>
                                <p className='uppercase font-semibold text-xs'>Passengers</p>
                                <p className='capitalize'>{vehicleData?.seat} Seats</p>
                            </div>
                        </div>
                        <div className='flex items-center justify-items-center gap-2'>
                            <div className='h-10 w-10 grid place-items-center p-2 rounded-full bg-gray-200'>
                                <img className='h-4 ' src='/mileage.png' />
                            </div>
                            <div className='text-sm'>
                                <p className='uppercase font-semibold text-xs'>Mileage:</p>
                                <p className='capitalize'>{vehicleData?.mileage} Km/L</p>
                            </div>
                        </div>
                        <div className='flex items-center justify-items-center gap-2'>
                            <div className='h-10 w-10 grid place-items-center p-2 rounded-full bg-gray-200'>
                                <img className='h-4 ' src='/year.png' />
                            </div>
                            <div className='text-sm'>
                                <p className='uppercase font-semibold text-xs'>Year:</p>
                                <p className='capitalize'>{vehicleData?.year} Model</p>
                            </div>
                        </div>
                        <div className='flex items-center justify-items-center gap-2'>
                            <div className='h-10 w-10 grid place-items-center p-2 rounded-full bg-gray-200'>
                                <img className='h-4 ' src='/petrol.png' />
                            </div>
                            <div className='text-sm'>
                                <p className='uppercase font-semibold text-xs'>Fuel:</p>
                                <p className='capitalize'>{vehicleData?.fuel_type}</p>
                            </div>
                        </div>
                        <div className='flex items-center justify-items-center gap-2'>
                            <div className='h-10 w-10 grid place-items-center p-2 rounded-full bg-gray-300'>
                                <img className='h-4 ' src='/engine.png' />
                            </div>
                            <div className='text-sm'>
                                <p className='uppercase font-semibold text-xs'>Engine:</p>
                                <p className='capitalize'>{vehicleData?.engine}</p>
                            </div>
                        </div>
                    </div>
                </div>

                {
                    isVehicleOwned ?
                        <>
                            <div className='grid gap-4 p-7 border-2 mt-5 rounded-xl shadow text-gray-500 relative'>

                                <button className='absolute right-2 top-2'
                                    onClick={() => {
                                        setOpenEditModal(true)
                                    }}>
                                    <BiEdit />
                                </button>

                                <p className='text-center text-2xl font-bold '>Booking Details</p>
                                <p className=''>Note: If changes in pick up and drop dates needs to be done, you should contact the admin before 24 hrs.</p>

                                <div className='grid gap-4 py-4'>
                                    <div className='flex gap-4'>
                                        <p className='w-1/4 font-semibold'>Pickup Date</p>
                                        <p>:</p>
                                        <p>{selectedVehicleData.pickup_date}</p>
                                    </div>
                                    <div className='flex gap-4'>
                                        <p className='w-1/4 font-semibold'>Drop Date</p>
                                        <p>:</p>
                                        <p>{selectedVehicleData.drop_date}</p>
                                    </div>
                                    <div className='flex gap-4'>
                                        <p className='w-1/4 font-semibold'>Address</p>
                                        <p>:</p>
                                        <p>{selectedVehicleData.address}</p>
                                    </div>
                                    <div className='flex gap-4'>
                                        <p className='w-1/4 font-semibold'>Contact</p>
                                        <p>:</p>
                                        <p>{selectedVehicleData.contact}</p>
                                    </div>
                                    <div className='flex gap-4'>
                                        <p className='w-1/4 font-semibold'>Price</p>
                                        <p>:</p>
                                        <p>Rs. {selectedVehicleData.price}</p>
                                    </div>
                                </div>
                            </div>
                        </>
                        :
                        <>
                            <div className="border-b border-gray-200 py-6">
                                <p className="text-lg leading-none font-semibold">Included in the Price</p>

                                <ul className='mt-4'>
                                    {
                                        includedInPrice.map((value, index) => (
                                            <li key={index} className='flex gap-2 items-center text-gray-600 mb-2'><CiCircleCheck color='green' size={20} /> {value}</li>
                                        ))
                                    }
                                </ul>
                            </div>
                            <div className="border-b border-gray-200 py-6">
                                <p className="text-lg leading-none font-semibold">Rental Policy</p>

                                <ul className='mt-4 pl-2'>
                                    <li className='text-gray-600 mb-2'><b>Pay only 15% now,</b> and the rest at the destination.</li>
                                    <li className='text-gray-600 mb-2'>Cancel up-to <b>48 hours before pick-up</b> and get a full refund.</li>
                                    <li className='text-gray-600 mb-2'>This vehicle requires a licence category <b>A1,</b> or equivalent.</li>
                                    <li className='text-gray-600 mb-2'>You’ll need to be at least <b>18 years old</b> to rent it with 12 months driving experience.</li>
                                    <li className='text-gray-600 mb-2'>A <b>refundable</b> security-deposit is required ( 24 € debit-card, ) on pickup.</li>
                                    <li className='text-gray-600 mb-2'>This car includes <b>unsizeed mileage </b> per day in the price.</li>
                                </ul>
                            </div>

                            <div>
                                {
                                    (isAuthenticated && vehicleData?.user?._id != userDetails?._id) &&
                                    <button className='btn-primary' onClick={() => {
                                        setModalIsOpen(true)
                                        setPackageList(vehicleData)
                                    }}>Book Now</button>
                                }
                            </div>
                        </>
                }
            </div>
        </div>
    )
}

export default SingleVehicle