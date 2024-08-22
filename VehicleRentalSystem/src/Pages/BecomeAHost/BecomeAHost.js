import toast from 'react-hot-toast'
import axios from '../../axios'
import React, { useEffect, useState } from 'react'
import { loadStripe } from '@stripe/stripe-js'
import Modal from 'react-modal'
import { BiLoader, BiSolidStar, BiStar } from 'react-icons/bi'
import { BsChevronDoubleRight } from 'react-icons/bs'
import { Link } from 'react-router-dom'
import Rating from 'react-rating'
import AddVehicle from './AddVehicle'
import EditVehicle from './EditVehicle'
import Swal from 'sweetalert2'
import dayjs from 'dayjs'
import VehicleLogs from './VehicleLogs'
import LoadMore from '../../components/LoadMore'


function BecomeAHost() {
    const [isAddModalOpen, setIsAddModalOpen] = useState(false);
    const [isEditModalOpen, setIsEditModalOpen] = useState(false);
    const [vehicleData, setVehicleData] = useState([])
    const [selectedVehicleData, setSelectedVehicleData] = useState("")
    const [totalVehicleCount, setTotalVehicleCount] = useState("")
    const [currentVehiclePage, setCurrentVehiclePage] = useState(1)
    const [totalPage, setTotalPage] = useState(1)
    const [vehiclePageSize, setVehiclePageSize] = useState(10)
    const [modalIsOpen, setModalIsOpen] = useState(false)
    const [isLoading, setIsLoading] = useState(false)
    const [tab, setTab] = useState(1)


    const [packageList, setPackageList] = useState()

    const closeAddModal = () => {
        setIsAddModalOpen(false);
    };
    const openAddModal = () => {
        setIsAddModalOpen(true);
    };

    const closeEditModal = () => {
        setIsEditModalOpen(false);
    };
    const openEditModal = () => {
        setIsEditModalOpen(true);
    };

    const closeModal = () => {
        setModalIsOpen(false)
        setPackageList(undefined)
    }

    const getMyVehicles = async () => {
        try {
            setIsLoading(true)
            let result = await axios.get("/vehicle/my-vehicle", {
                params: {
                    page: currentVehiclePage,
                    size: vehiclePageSize,
                },
            });

            if (result.data.success) {
                setIsLoading(false)
                setVehicleData([...vehicleData, ...result.data.data]);
                setTotalVehicleCount(result.data.totalCount);
                setTotalPage(Math.ceil(result.data.totalCount / Number(result.data.size)));
            } else toast.error("Failed");
        } catch (ERR) {
            setIsLoading(false)
            console.log(ERR);
            toast.error(ERR.response.data.msg);
        }
    }



    useEffect(() => {
        getMyVehicles()
    }, [currentVehiclePage])


    const removeItem = async (id) => {
        try {
            Swal.fire({
                title: "Are you sure?",
                text: "You won't be able to revert this!",
                icon: "warning",
                showCancelButton: true,
                confirmButtonColor: "#3085d6",
                cancelButtonColor: "#d33",
                confirmButtonText: "Yes, Delete it!",
            }).then(async (result) => {
                if (result.isConfirmed) {
                    let result = await axios.delete("vehicle/" + id);
                    if (result.data.success) {
                        getMyVehicles();
                        toast.success("Deleted Successfully");
                    }
                }
            });
        } catch (ERR) {
            console.log(ERR);
            toast.error(ERR.response.data.msg);
        }
    };

    const makePayment = async (value, type) => {
        try {
            setIsLoading(true)
            const stripe = await loadStripe(process.env.REACT_APP_STRIPE_PL)

            // const body = {
            //     lesson_name: "",
            //     lesson: "lessoniD",
            //     lesson_type: "private",
            //     price: "400"
            // }
            const body = {
                lesson_name: value?.name,
                lesson: packageList?._id,
                lesson_type: type,
                price: value[type]
            }

            const response = await axios.post(`${process.env.REACT_APP_BASE_URI}booking/create-intent`, body)
            const result = stripe.redirectToCheckout({
                vehicleId: response.data.id
            })
            if ((await result).error) {
                setTimeout(() => {
                    setIsLoading(false)
                }, 500)
                console.log((await result).error)
            }
        } catch (error) {
            setTimeout(() => {
                setIsLoading(false)
                toast.error(error.response.data.msg)
            }, 500)
            console.log(error)
        }
    }

   

    return (
        <div className='max-w-7xl mx-auto p-5'>

            {isAddModalOpen && (
                <AddVehicle
                    closeModal={closeAddModal}
                    modalIsOpen={isAddModalOpen}
                    getRoute={getMyVehicles}
                />
            )}
            {isEditModalOpen && (
                <EditVehicle
                    closeModal={closeEditModal}
                    modalIsOpen={isEditModalOpen}
                    getRoute={getMyVehicles}
                    data={selectedVehicleData}
                />
            )}

            {
                isLoading &&
                <div className='fixed h-screen top-0 w-full bg-black bg-opacity-65 z-[999999] grid place-items-center'>
                    <label className='flex items-center gap-3 font-semibold text-white'><BiLoader className='animate-spin' /> Loading... </label>
                </div>
            }

            <div className='max-w-7xl mx-auto py-10 px-5 mb-10'>
                <h1 className='lg:text-5xl text-4xl font-bold text-center '> {tab === 1 ? "Add Your Vehicles To Rent" : "Your Vehicle Log"}</h1>
            </div>

            <div className='flex justify-end gap-4'>
                {
                    tab === 1 ?
                        <button onClick={() => {
                            setTab(2)
                        }} className='btn-primary'>Vehicle Log</button>
                        :
                        <button onClick={() => {
                            setTab(1)
                        }} className='btn-success'>My Vehicles</button>
                }

                <button onClick={() => {
                    openAddModal()
                }} className='btn-dark'>Add Vehicle</button>
            </div>

            {
                tab === 1 &&
                <>
                    <div className='grid   gap-7 mt-10'>
                        {
                            vehicleData &&
                            (vehicleData.length === 0 ?
                                <p className='p-5 font-semibold text-red-800'>No Vehicles Yet</p> :
                                vehicleData.map((value, index) => (
                                    <div className={` grid grid-cols-6 border  rounded-2xl  overflow-hidden relative`} key={index}>
                                        {/* <img className='w-full h-64 mb-5 object-cover' src={`${value?.images[0]}`} /> */}
                                        <div className='h-80  col-span-2  '>
                                            <img className='w-full  h-full object-cover' src={`${process.env.REACT_APP_IMG_URI}${value?.images[0]}`} />
                                        </div>

                                        <div className='p-4 col-span-3 px-8 w-full'>
                                            {/* <Rating initialRating={4.5} step={1} readonly fullSymbol={<BiSolidStar size={20} fill='#FFA128' />} emptySymbol={<BiStar size={20} fill='#FFA128' />} /> */}
                                            <p className={`w-fit text-sm  font-semibold   rounded-2xl ${value.is_active ? "text-green-500" : "text-red-500"} `}> {value.is_active ? "Verified" : "Not Verified !!"} </p>
                                            <h2 className='lg:text-2xl text-xl font-bold my-3 capitalize'>{value?.name}</h2>
                                            <p> <b className='text-blue-700'>Rs. {value.price}</b> / Day</p>

                                            <div className='grid xl:grid-cols-3 lg:grid-cols-2 md:grid-cols-1 sm:grid-cols-2 grid-cols-2 justify-center gap-8 mt-10 mb-3 '>
                                                <div className='flex items-center  gap-2'>
                                                    <div className='h-10 w-10 grid place-items-center p-2 rounded-full bg-gray-200'>
                                                        <img className='h-4 ' src='/seat.png' />
                                                    </div>
                                                    <div className='text-sm'>
                                                        <p className='uppercase font-semibold text-xs'>Passengers</p>
                                                        <p className='capitalize'>{value?.seat} Seats</p>
                                                    </div>
                                                </div>
                                                <div className='flex items-center justify-items-center gap-2'>
                                                    <div className='h-10 w-10 grid place-items-center p-2 rounded-full bg-gray-200'>
                                                        <img className='h-4 ' src='/mileage.png' />
                                                    </div>
                                                    <div className='text-sm'>
                                                        <p className='uppercase font-semibold text-xs'>Mileage:</p>
                                                        <p className='capitalize'>{value?.mileage} Km/L</p>
                                                    </div>
                                                </div>
                                                <div className='flex items-center justify-items-center gap-2'>
                                                    <div className='h-10 w-10 grid place-items-center p-2 rounded-full bg-gray-200'>
                                                        <img className='h-4 ' src='/year.png' />
                                                    </div>
                                                    <div className='text-sm'>
                                                        <p className='uppercase font-semibold text-xs'>Year:</p>
                                                        <p className='capitalize'>{value?.year} Model</p>
                                                    </div>
                                                </div>
                                                <div className='flex items-center justify-items-center gap-2'>
                                                    <div className='h-10 w-10 grid place-items-center p-2 rounded-full bg-gray-200'>
                                                        <img className='h-4 ' src='/petrol.png' />
                                                    </div>
                                                    <div className='text-sm'>
                                                        <p className='uppercase font-semibold text-xs'>Fuel:</p>
                                                        <p className='capitalize'>{value?.fuel_type}</p>
                                                    </div>
                                                </div>
                                                <div className='flex items-center justify-items-center gap-2'>
                                                    <div className='h-10 w-10 grid place-items-center p-2 rounded-full bg-gray-300'>
                                                        <img className='h-4 ' src='/engine.png' />
                                                    </div>
                                                    <div className='text-sm'>
                                                        <p className='uppercase font-semibold text-xs'>Engine:</p>
                                                        <p className='capitalize'>{value?.engine}</p>
                                                    </div>
                                                </div>
                                            </div>

                                        </div>
                                        <div className='col-span-1 grid items-center p-4'>
                                            <button className='btn-primary' onClick={() => {
                                                setSelectedVehicleData(value)
                                                openEditModal()
                                            }}>Edit Information</button>
                                            <button className='btn-danger' onClick={() => {
                                                removeItem(value?._id)
                                            }}>Delete</button>
                                        </div>
                                    </div>
                                )))
                        }
                    </div>
                    <div>
                        <LoadMore loading={isLoading} setLoading={setIsLoading} page={currentVehiclePage} setPage={setCurrentVehiclePage} totalPage={totalPage} />
                    </div>
                </>

            }


            {
                tab === 2 &&
                <VehicleLogs loading={isLoading} setLoading={setIsLoading}/>

            }

        </div >
    )
}

export default BecomeAHost