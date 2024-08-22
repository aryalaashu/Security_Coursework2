import axios from '../../axios'
import React, { useEffect, useState } from 'react'
import toast from 'react-hot-toast'
import { BiTennisBall, BiUser } from 'react-icons/bi'
import { FaBoxes, FaCarSide, FaShoppingBag, FaShoppingCart, FaUsers, FaVehicle } from 'react-icons/fa'
import { MdEventSeat } from 'react-icons/md'

function Dashboard() {
  const [totalUserCount, setTotalUserCount] = useState(0)
  const [totalVehicleCount, setTotalVehicleCount] = useState(0)
  const [totalContactCount, setTotalContactCount] = useState(0)

  const getAllContact = async (values, actions) => {
    try {
      let result = await axios.get('/contact', {
        params: {
          search: "",
          page: 1,
          size: 1
        }
      })

      if (result.data.success) {
        setTotalContactCount(result?.data?.totalCount)
      } else toast.error('Failed')

    } catch (ERR) {
      console.log(ERR)
      // toast.error(ERR.response.data.msg)
    }
  }

  const getAllVehicle = async () => {
    try {
      let result = await axios.get('/vehicle', {
        params: {
          search: "",
          page: 1,
          size: 1
        }
      })

      if (result.data.success) {
        setTotalVehicleCount(result.data.totalCount)
      } else toast.error('Failed')
    } catch (ERR) {
      console.log(ERR)
      // toast.error(ERR.response.data.msg)
    }
  }

  const getAllUsers = async () => {
    try {
      let result = await axios.get('/user/all', {
        params: {
          search: "",
          page: 1,
          size: 1
        }
      })

      if (result.data.success) {
        setTotalUserCount(result.data.totalCount)
      } else toast.error('Failed')
    } catch (ERR) {
      console.log(ERR)
      // toast.error(ERR.response.data.msg)
    }
  }

  useEffect(() => {
    getAllContact()
    getAllUsers()
    getAllVehicle()
  }, [])

  return (
    <div className='mx-auto max-w-7xl px-4'>

      <h1 className='text-4xl font-semibold'>Admin Dashboard</h1>

      <div className='grid md:grid-cols-2 gap-4 mt-10'>

        <div className='shadow p-3 py-10 bg-blue-100 flex flex-col items-center'>
          <label className='font-semibold text-xl flex items-center gap-3'><FaCarSide /> Total Vehicles</label>
          <label className='text-4xl mt-3 text-gray-500'>{totalVehicleCount}</label>
        </div>
        {/* <div className='shadow p-3 py-10 flex bg-yellow-200 flex-col items-center'>
          <label className='font-semibold text-xl flex items-center gap-3'><BiTennisBall /> Total Sessions</label>
          <label className='text-4xl mt-3 text-gray-500'>{totalSessionsCount}</label>
        </div> */}
        <div className='shadow p-3 py-10 flex bg-green-200 flex-col items-center'>
          <label className='font-semibold text-xl flex items-center gap-3'><BiUser /> Total Contact</label>
          <label className='text-4xl mt-3 text-gray-500'>{totalContactCount}</label>
        </div>
        <div className='shadow p-3 py-10 bg-orange-200 flex flex-col items-center'>
          <label className='font-semibold text-xl flex items-center gap-3'><FaUsers /> Total Users</label>
          <label className='text-4xl mt-3 text-gray-500'>{totalUserCount}</label>
        </div>
      </div>
    </div>
  )
}

export default Dashboard