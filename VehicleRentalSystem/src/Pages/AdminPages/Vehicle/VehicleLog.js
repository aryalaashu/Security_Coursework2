import axios from '../../../axios'
import { Field, Form, Formik } from 'formik'
import React, { useEffect, useState } from 'react'
import toast from 'react-hot-toast'
import Modal from 'react-modal'
import * as yup from 'yup';
import FieldError from '../../../components/FieldError'
import Select from 'react-select'
import dayjs from 'dayjs'
import ReactSelect from '../../../components/ReactSelect'
import { BiCheck } from 'react-icons/bi'

function VehicleLog({ modalIsOpen, closeModal, getRoute, data }) {

    const [userData, setUserData] = useState()
    const [currentUserPage, setCurrentUserPage] = useState()
    const [userPageSize, setUserPageSize] = useState(1)
    const [totalUserPage, setTotalUserPage] = useState(1)
    const [totalUserCount, setTotalUserCount] = useState()

    const handleFormSubmit = async (values, actions) => {
        try {
            let result = await axios.put('/user/' + data?.userSlug, values)

            if (result.data.success) {
                toast.success('User Edited Successfully')
                closeModal()
                getRoute()
            } else toast.error('Failed')
        } catch (ERR) {
            console.log(ERR)
            toast.error(ERR.response.data.msg)
        }
    }

    const getData = async (values, actions) => {
        try {
            let result = await axios.get('/vehicle-register/' + data?._id)

            if (result.data.success) {
                setUserData(result.data.data.data)
                setTotalUserPage(result.data.data.totalPage)
                setTotalUserCount(result.data.data.count)
                // toast.success('User Edited Successfully')
            } else toast.error('Failed')
        } catch (ERR) {
            console.log(ERR)
            toast.error(ERR.response.data.msg)
        }
    }

    const approveStatus = async (status, userId) => {
        try {
            let result = await axios.put(`vehicle-register/${data?._id}/${userId}`, {
                approved: status === true ? false : true
            })

            if (result.data.success) {
                getData()
                // toast.success('User Edited Successfully')
            } else toast.error('Failed')
        } catch (ERR) {
            console.log(ERR)
            toast.error(ERR.response.data.msg)
        }
    }

    useEffect(() => {
        getData()
    }, [])


    return (
        <Modal
            ariaHideApp={false}
            isOpen={modalIsOpen}
            onRequestClose={closeModal}
            contentLabel="Vehicle Attendance"
            overlayClassName="Overlay"
            className="Modal rounded-md p-5 w-full max-w-7xl max-h-screen overflow-auto"
        >
            <h1 className="text-4xl font-bold tracking-tight text-gray-900">Vehicle Registrations of {data?.vehicleName}</h1>

            <div className='w-full my-5  bg-white'>
                <table className="table-auto rounded-lg border w-full text-left ">
                    <thead className='font-semibold border-b bg-blue-100'>
                        <tr className='opacity-75'>
                            <th className='p-3'>S.N</th>
                            <th className='p-3'>Full Name</th>
                            <th className='p-3'>Email</th>
                            <th className='p-3'>Status</th>
                            <th className='p-3'>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {
                            userData &&
                            (userData.length === 0 ?
                                <p className='p-5 font-semibold text-red-800'>No Data</p> :
                                userData.map((value, index) => (
                                    <tr key={index} className='border-b'>
                                        <td className='p-3'>{index + 1}</td>
                                        <td className='p-3'>{value?.user?.firstname} {value?.user?.lastname}</td>
                                        <td className='p-3'>{value?.user?.email}</td>
                                        {value?.approved ?
                                            <td className='p-3 text-green-700 font-semibold'>Approved</td>
                                            :
                                            <td className='p-3 text-green-700 font-semibold'>Not Approved</td>}
                                        <td className='p-3 flex gap-2 flex-wrap max-w-fit'>
                                            <button onClick={() => {
                                                approveStatus(value?.approved, value?.user?._id)
                                                // setSelectedUserData(value)
                                                // openEditModal()
                                            }} className='bg-blue-700 text-white p-2 rounded'>
                                                <BiCheck />
                                            </button>
                                        </td>
                                    </tr>
                                )))
                        }

                    </tbody>
                </table>
                <div className="flex items-center justify-between border-t border-gray-200 bg-white px-4 py-3 sm:px-6">
                    <div className="flex flex-1 justify-between sm:hidden">
                        <button className="relative inline-flex items-center rounded-md border border-gray-300 bg-white px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50">Previous</button>
                        <button className="relative ml-3 inline-flex items-center rounded-md border border-gray-300 bg-white px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50">Next</button>
                    </div>
                    <div className="hidden sm:flex sm:flex-1 sm:items-center sm:justify-between">
                        <div className='text-sm text-gray-700'>
                            <p className="font-semibold">
                                {totalUserCount} Total Results
                            </p>
                        </div>
                        <div className='flex flex-wrap items-center gap-3'>
                            <label>Showing</label>
                            <select defaultValue={userPageSize} className='border rounded py-1' onChange={(e) => {
                                setCurrentUserPage(1)
                                setUserPageSize(e.target.value)
                            }}>
                                <option>1</option>
                                <option>5</option>
                                <option>10</option>
                                <option>20</option>
                            </select>
                            <nav className="isolate inline-flex -space-x-px rounded-md shadow-sm" aria-label="Pagination">
                                <button
                                    disabled={currentUserPage === 1}
                                    onClick={() => {
                                        setCurrentUserPage(currentUserPage - 1)
                                    }} className="relative inline-flex items-center rounded-l-md px-2 py-2 text-gray-400 ring-1 ring-inset ring-gray-300 hover:bg-gray-50 focus:z-20 focus:outline-offset-0">
                                    <span className="sr-only">Previous</span>
                                    <svg className="h-5 w-5" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                        <path fillRule="evenodd" d="M12.79 5.23a.75.75 0 01-.02 1.06L8.832 10l3.938 3.71a.75.75 0 11-1.04 1.08l-4.5-4.25a.75.75 0 010-1.08l4.5-4.25a.75.75 0 011.06.02z" clipRule="evenodd" />
                                    </svg>
                                </button>

                                <span className="relative inline-flex items-center px-4 py-2 text-sm font-semibold text-gray-900 ring-1 ring-inset ring-gray-300 hover:bg-gray-50 focus:z-20 focus:outline-offset-0">
                                    Page {currentUserPage} of {totalUserPage}
                                </span>

                                <button
                                    disabled={currentUserPage === totalUserPage}
                                    onClick={() => {
                                        setCurrentUserPage(currentUserPage + 1)
                                    }} className="relative inline-flex items-center rounded-r-md px-2 py-2 text-gray-400 ring-1 ring-inset ring-gray-300 hover:bg-gray-50 focus:z-20 focus:outline-offset-0">
                                    <span className="sr-only">Next</span>
                                    <svg className="h-5 w-5" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                        <path fillRule="evenodd" d="M7.21 14.77a.75.75 0 01.02-1.06L11.168 10 7.23 6.29a.75.75 0 111.04-1.08l4.5 4.25a.75.75 0 010 1.08l-4.5 4.25a.75.75 0 01-1.06-.02z" clipRule="evenodd" />
                                    </svg>
                                </button>
                            </nav>
                        </div>
                    </div>
                </div>
            </div>

        </Modal>
    )
}

export default VehicleLog