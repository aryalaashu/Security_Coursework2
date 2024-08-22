import dayjs from 'dayjs'
import React, { useEffect, useState } from 'react'
import EditBookingModal from '../Vehicle/EditBookingModal'
import { BiEdit } from 'react-icons/bi'
import axios from '../../axios'
import toast from 'react-hot-toast'
import Swal from 'sweetalert2'
import LoadMore from '../../components/LoadMore'

function VehicleLogs({ loading, setLoading }) {

    const [bookingForOwner, setBookingForOwner] = useState([])
    const [currentVehiclePage, setCurrentVehiclePage] = useState(1)
    const [totalPage, setTotalPage] = useState(1)

    const vehicleHistory = async () => {
        try {
            setLoading(true)
            let result = await axios.get("/booking/booking-for-owner", {
                params: {
                    page: currentVehiclePage,
                    size: 9999,
                },
            });

            if (result.data.success) {
                setLoading(false)
                setBookingForOwner(result.data.data);
                setTotalPage(Math.ceil(result.data.totalCount / Number(result.data.size)))
            } else toast.error("Failed");
        } catch (ERR) {
            console.log(ERR);
            setLoading(false)
            toast.error(ERR.response.data.msg);
        }
    }
    useEffect(() => {
        vehicleHistory()
    }, [currentVehiclePage])

    const [openEditModal, setOpenEditModal] = useState(false)
    const [selectedVehicleData, setSelectedVehicleData] = useState()


    const closeEditBookingModal = () => {
        setOpenEditModal(false)
    }

    const changeStatus = async (id, status) => {
        try {
            Swal.fire({
                title: "Are you sure?",
                text: "You won't be able to revert this!",
                icon: "warning",
                showCancelButton: true,
                confirmButtonColor: "#3085d6",
                cancelButtonColor: "#d33",
                confirmButtonText: "Yes, Change the Status!",
            }).then(async (result) => {
                if (result.isConfirmed) {
                    let result = await axios.put("booking/" + id, {
                        status: status
                    });
                    if (result.data.success) {
                        vehicleHistory();
                        toast.success("Status Changed Successfully");
                    }
                }
            });
        } catch (ERR) {
            console.log(ERR);
            toast.error(ERR.response.data.msg);
        }
    };

    return (
        <>
            <div className='grid gap-7 mt-10'>

                {
                    openEditModal &&
                    <EditBookingModal
                        closeModal={closeEditBookingModal}
                        getRoute={vehicleHistory}
                        modalIsOpen={openEditModal}
                        data={selectedVehicleData}
                        isOwner={true}
                    />
                }


                {
                    bookingForOwner &&
                    (bookingForOwner.length === 0 ?
                        <p className='p-5 font-semibold text-red-800'>No Vehicles Yet</p> :
                        bookingForOwner.map((value, index) => (
                            <div key={index} className={` grid grid-cols-6 border  rounded-2xl  overflow-hidden relative`}>
                                {/* <img className='w-full h-64 mb-5 object-cover' src={`${value?.images[0]}`} /> */}
                                <div className='h-80  col-span-2  '>
                                    <img className='w-full  h-full object-cover' src={`${process.env.REACT_APP_IMG_URI}${value?.vehicle.images[0]}`} />
                                </div>

                                <div className='p-4 col-span-3 px-8 w-full'>
                                    {/* <Rating initialRating={4.5} step={1} readonly fullSymbol={<BiSolidStar size={20} fill='#FFA128' />} emptySymbol={<BiStar size={20} fill='#FFA128' />} /> */}
                                    <div>
                                        <select className='inputfield w-fit' value={value.status} onChange={(e) => {
                                            changeStatus(value?._id, e.target.value)
                                        }}>
                                            <option value={''}>Change Status</option>
                                            <option value={'booked'}>Booked</option>
                                            <option value={'delivered'}>Delivered</option>
                                            <option value={'returned'}>Returned</option>
                                        </select>
                                        {/* <p className={`w-fit text-sm uppercase font-semibold rounded-2xl  } `}> Set as Returned </p> */}
                                        {/* <span className={`w-fit text-sm uppercase font-semibold rounded-2xl ${value.status ? "text-green-500" : "text-blue-500"} `}> {value.status ? value.status : 'returned'} </span> */}
                                    </div>

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
                                <div className='col-span-1 grid place-items-center p-4 text-sm'>
                                    <div>
                                        <button className='absolute right-2 top-2'
                                            onClick={() => {
                                                setSelectedVehicleData(value)
                                                setOpenEditModal(true)
                                            }}>
                                            <BiEdit />
                                        </button>
                                        <p>
                                            Booked By: {value.user.firstname} {value.user.lastname}
                                        </p>
                                        <p>
                                            Pickup Date: {dayjs(value.pickup_date).format('MMM DD, YYYY')}
                                        </p>
                                        <p>
                                            Drop Date: {dayjs(value.drop_date).format('MMM DD, YYYY')}
                                        </p>
                                    </div>
                                </div>
                            </div>
                        )))
                }
            </div>
            {/* <div>
                <LoadMore  loading={loading} setLoading={setLoading} page={currentVehiclePage} setPage={setCurrentVehiclePage} totalPage={totalPage} />
            </div> */}
        </>
    )
}

export default VehicleLogs