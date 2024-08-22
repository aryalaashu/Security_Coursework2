import toast from 'react-hot-toast'
import axios from '../../axios'
import React, { useEffect, useState } from 'react'
import { loadStripe } from '@stripe/stripe-js'
import Modal from 'react-modal'
import { BiLoader, BiSolidStar, BiStar } from 'react-icons/bi'
import { BsChevronDoubleRight } from 'react-icons/bs'
import { Link } from 'react-router-dom'
import Rating from 'react-rating'
import Swal from 'sweetalert2'

function MyRentals() {
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [isEditModalOpen, setIsEditModalOpen] = useState(false);
  const [vehicleData, setVehicleData] = useState([])
  const [keyword, setKeyword] = useState("")

  const [currentVehiclePage, setCurrentVehiclePage] = useState(1)
  const [vehiclePageSize, setVehiclePageSize] = useState(10)
  const [selectedVehicleData, setSelectedVehicleData] = useState("")
  const [vehicleType, setVehicleType] = useState("")
  const [modalIsOpen, setModalIsOpen] = useState(false)
  const [isLoading, setIsLoading] = useState(false)

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

  const getMyBookings = async () => {
    try {
      let result = await axios.get("/booking/my-booking", {
        params: {
          search: keyword,
          page: currentVehiclePage,
          size: vehiclePageSize,
          type: vehicleType
        },
      });

      if (result.data.success) { 
        setVehicleData(result.data.data);
        // setTotalVehicleCount(result.data.totalCount);
        // setTotalVehiclePage(result.data.totalPage);
      } else toast.error("Failed");
    } catch (ERR) {
      console.log(ERR);
      toast.error(ERR.response.data.msg);
    }
  }

  useEffect(() => {
    getMyBookings()
  }, [vehicleType, keyword])

  return (
    <div className='max-w-7xl mx-auto p-5'>

      {
        isLoading &&
        <div className='fixed h-screen top-0 w-full bg-black bg-opacity-65 z-[999999] grid place-items-center'>
          <label className='flex items-center gap-3 font-semibold text-white'><BiLoader className='animate-spin' /> Loading... </label>
        </div>
      }

      <div className='max-w-7xl mx-auto py-10 px-5 mb-10'>
        <h1 className='lg:text-5xl text-4xl font-bold text-center '>My Rentals</h1>
      </div>

      <div className='grid md:grid-cols-3 gap-7'>
        <select onChange={(e) => {
          setVehicleType(e.target.value)
        }} className='inputfield'>
          <option value={""}>Sort By Vehicle type</option>
          <option value={"two-wheeler"}>Two Wheeler</option>
          <option value={"four-wheeler"}>Four-Wheeler</option>
        </select>
        <span />

        <input type='string' className='inputfield' onChange={(e) => {
          setKeyword(e.target.value)
        }} placeholder='Search Here..............' />
      </div>


      <div className='grid   gap-7 mt-10'>
        {
          vehicleData &&
          (vehicleData.length === 0 ?
            <p className='p-5 font-semibold text-red-800'>No Vehicles Yet</p> :
            vehicleData.map((value, index) => (
              <div key={index} className={` grid grid-cols-6 border  rounded-2xl  overflow-hidden`}>
                {/* <img className='w-full h-64 mb-5 object-cover' src={`${value?.images[0]}`} /> */}
                <div className='h-80  col-span-2  '>
                  <img className='w-full  h-full object-cover' src={`${process.env.REACT_APP_IMG_URI}${value?.vehicle?.images[0]}`} />
                </div>

                <div className='p-4 col-span-3 px-8 w-full'>
                  {/* <Rating initialRating={4.5} step={1} readonly fullSymbol={<BiSolidStar size={20} fill='#FFA128' />} emptySymbol={<BiStar size={20} fill='#FFA128' />} /> */}
                  <h2 className='lg:text-2xl text-xl font-bold my-3 capitalize'>{value?.vehicle?.name}</h2>
                  <p> <b className='text-blue-700'>Rs. {value.vehicle?.price}</b> / Day</p>

                  <div className='grid xl:grid-cols-3 lg:grid-cols-2 md:grid-cols-1 sm:grid-cols-2 grid-cols-2 justify-center gap-8 mt-10 mb-3 '>
                    <div className='flex items-center  gap-2'>
                      <div className='h-10 w-10 grid place-items-center p-2 rounded-full bg-gray-200'>
                        <img className='h-4 ' src='/seat.png' />
                      </div>
                      <div className='text-sm'>
                        <p className='uppercase font-semibold text-xs'>Passengers</p>
                        <p className='capitalize'>{value?.vehicle?.seat} Seats</p>
                      </div>
                    </div>
                    <div className='flex items-center justify-items-center gap-2'>
                      <div className='h-10 w-10 grid place-items-center p-2 rounded-full bg-gray-200'>
                        <img className='h-4 ' src='/mileage.png' />
                      </div>
                      <div className='text-sm'>
                        <p className='uppercase font-semibold text-xs'>Mileage:</p>
                        <p className='capitalize'>{value?.vehicle?.mileage} Km/L</p>
                      </div>
                    </div>
                    <div className='flex items-center justify-items-center gap-2'>
                      <div className='h-10 w-10 grid place-items-center p-2 rounded-full bg-gray-200'>
                        <img className='h-4 ' src='/year.png' />
                      </div>
                      <div className='text-sm'>
                        <p className='uppercase font-semibold text-xs'>Year:</p>
                        <p className='capitalize'>{value?.vehicle?.year} Model</p>
                      </div>
                    </div>
                    <div className='flex items-center justify-items-center gap-2'>
                      <div className='h-10 w-10 grid place-items-center p-2 rounded-full bg-gray-200'>
                        <img className='h-4 ' src='/petrol.png' />
                      </div>
                      <div className='text-sm'>
                        <p className='uppercase font-semibold text-xs'>Fuel:</p>
                        <p className='capitalize'>{value?.vehicle?.fuel_type}</p>
                      </div>
                    </div>
                    <div className='flex items-center justify-items-center gap-2'>
                      <div className='h-10 w-10 grid place-items-center p-2 rounded-full bg-gray-300'>
                        <img className='h-4 ' src='/engine.png' />
                      </div>
                      <div className='text-sm'>
                        <p className='uppercase font-semibold text-xs'>Engine:</p>
                        <p className='capitalize'>{value?.vehicle?.engine}</p>
                      </div>
                    </div>
                  </div>

                </div>
                <div className='col-span-1 grid items-center p-4'>
                  <Link to={'/vehicle/' + value?.vehicle?.sku} className='!justify-center gap-2 btn-primary rounded-xl w-full'>View Details </Link>
                </div>
              </div>
            )))
        }
      </div>
    </div >
  )
}

export default MyRentals