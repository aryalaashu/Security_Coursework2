import axios from '../../axios'
import React, { useContext, useEffect, useRef, useState } from 'react'
import EditProfile from './EditProfile'
import toast from 'react-hot-toast'
import { AuthContext } from '../../context/authContext'
import { Link } from 'react-router-dom'
import { CgAlarm } from 'react-icons/cg'
import dayjs from 'dayjs'
import ConfirmPassword from './ConfirmPassword'
import { BiLinkExternal } from 'react-icons/bi'
import BookingSpending from './BookingSpending'
import MyIncome from './MyIncome'

function Profile() {
    const { userDetails, setUserDetails } = useContext(AuthContext)
    const [profileDetails, setProfileDetails] = useState([])
    const [editProfile, setEditProfile] = useState()
    const [bookingData, setBookingData] = useState()
    const [notices, setNotices] = useState()

    const openEditProfile = () => {
        setEditProfile(true)
    }

    const closeEditProfile = () => {
        setEditProfile(false)
    }

    const uploadRef = useRef()

    const getProfileDetails = async () => {
        try {
            let result = await axios.get('/user/my-profile/')
            if (result.data.success) {
                setProfileDetails(result.data.data)
            }
        } catch (ERR) {
            console.log(ERR)
        }
    }

    const getBookings = async () => {
        try {
            let result = await axios.get('/booking/my-booking/')
            if (result.data.success) {
                setBookingData(result.data.data.data)

            }
        } catch (ERR) {
            console.log(ERR)
        }
    }

    const getNotices = async () => {
        try {
            let result = await axios.get('/notice')
            if (result.data.success) {
                setNotices(result.data.data.data) 

            }
        } catch (ERR) {
            console.log(ERR)
        }
    }

    const uploadProfilePicture = async (img) => {
        try {
            if (img) {
                const formData = new FormData()

                formData.append('image', img)
                let result = await axios.put('/user/upload-pp', formData)
                if (result.data.success) {
                    toast.success('Image Uploaded')
                    const localData = JSON.parse(localStorage.getItem('_hw_userDetails'))
                    localData.image = result.data?.data?.image
                    localStorage.setItem('_hw_userDetails', JSON.stringify(localData))
                    getProfileDetails()
                    userDetails.image = result.data?.data?.image
                    // setUserDetails(newdata)
                    setUserDetails(userDetails)
                }
            }
        } catch (ERR) {
            console.log(ERR)
            toast.error(ERR.response.data.msg || "Failed to change image, try again later")
        }
    }

    useEffect(() => {
        getProfileDetails()
    }, [])

    const [tab, setTab] = useState(1)

    const renderUI = (tab) => {
        try {
            switch (tab) {
                case 1:
                    return <EditProfile modalIsOpen={editProfile} closeModal={closeEditProfile} getRoute={getProfileDetails} profileDetails={profileDetails} />
                case 2:
                    return <ConfirmPassword />
                case 3:
                    return <BookingSpending />
                case 4:
                    return <MyIncome />
            }
        } catch (ERR) {
            console.log(ERR)
        }
    }


    return (
        <div className="h-full bg-gray-50 p-8 container mx-auto">

            <div className='grid grid-cols-8 gap-5'>
                <div className=' col-span-2 rounded-lg border bg-white'>
                    <ul className='space-y-3 p-6'>
                        {
                            userDetails.role.includes('superadmin') &&
                            <li className='   '>
                                <Link to={'/dashboard'} className={`w-full flex items-center gap-2 bg-blue-200  p-4 border border-transparent rounded-lg `}> Go To Dashboard  <BiLinkExternal /> </Link>
                            </li>
                        }
                        <li onClick={() => {
                            setTab(1)
                        }} className={`${tab === 1 ? "bg-gray-200" : "bg-white"} p-4 border border-transparent rounded-lg cursor-pointer `}><p>Profile Settings</p><p className='text-xs'>Edit Personal Information and Login Credentials</p></li>
                        <li onClick={() => {
                            setTab(2)
                        }} className={`${tab === 2 ? "bg-gray-200" : "bg-white"} p-4 border border-transparent rounded-lg cursor-pointer `}><p>Change Password</p><p className='text-xs'>Change Password of the System</p></li>
                        <li onClick={() => {
                            setTab(3)
                        }} className={`${tab === 3 ? "bg-gray-200" : "bg-white"} p-4 border border-transparent rounded-lg cursor-pointer `}><p>My Booking Spendings</p><p className='text-xs'>View the total details of your booking transaction</p></li>
                        <li onClick={() => {
                            setTab(4)
                        }} className={`${tab === 4 ? "bg-gray-200" : "bg-white"} p-4 border border-transparent rounded-lg cursor-pointer `}><p>My Income</p><p className='text-xs'>See the total transaction amount from your added vehicle</p></li>
                    </ul>
                </div>
                <div className='col-span-6'>
                    {
                        renderUI(tab)
                    }
                </div>
            </div>


        </div >
    )
}

export default Profile