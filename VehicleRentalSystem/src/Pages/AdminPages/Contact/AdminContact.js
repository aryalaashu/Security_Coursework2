import React, { useEffect, useState } from 'react'
import axios from '../../../axios'
import toast from 'react-hot-toast'

function AdminContact() {

  const [contactData, setContactData] = useState([])

  const [totalContactCount, setTotalContactCount] = useState(0)
  const [currentContactPage, setCurrentContactPage] = useState(1)
  const [totalContactPage, setTotalContactPage] = useState(1)
  const [contactPageSize, setContactPageSize] = useState(10)
  // const [keyword, setKeyword] = useState("")



  useEffect(() => {
    const getAllContact = async (values, actions) => {
      try {
        let result = await axios.get('/contact', {
          params: {
            search: '',
            page: currentContactPage,
            size: contactPageSize
          }
        })

        if (result.data.success) {
          setContactData(result?.data?.data)
          setTotalContactCount(result?.data?.totalCount)
          setTotalContactPage(Math.ceil(result.data.totalCount / Number(result.data.size)))
        } else toast.error('Failed')
      } catch (ERR) {
        console.log(ERR)
        toast.error(ERR.response.data.msg)
      }
    }
    getAllContact()
  }, [currentContactPage, contactPageSize])

  return (
    <div className='mx-auto max-w-7xl w-full px-4'>

      <div className="flex items-baseline justify-between  pb-6 pt-5">
        <h1 className="text-4xl font-bold tracking-tight text-gray-900">Contacts</h1>
      </div>

      {/* <div>
        <input className='border p-2' type='string' placeholder='Search' onChange={(e) => {
          setKeyword(e.target.value)
          setCurrentContactPage(1)
        }} />
      </div> */}

      <div className='w-full my-5  bg-white'>
        <table className="table-auto w-full rounded-lg border text-left ">
          <thead className='font-semibold border-b bg-blue-100'>
            <tr className='opacity-75'>
              <th className='p-3'>S.N</th>
              <th className='p-3'>Full Name</th>
              <th className='p-3'>Contact</th>
              <th className='p-3'>Email</th>
              <th className='p-3'>Message</th>
            </tr>
          </thead>
          <tbody>
            {
              contactData &&
              (contactData?.length === 0 ?
                <p className='p-5 font-semibold text-red-800'>No Data</p> :
                contactData?.map((value, index) => (
                  <tr key={index} className='border-b'>
                    <td className='p-3'>{index + 1}</td>
                    <td className='p-3'>{value?.name}</td>
                    <td className='p-3'>{value?.mobile_no}</td>
                    <td className='p-3'>{value?.email}</td>
                    <td className='p-3'>{value?.message}</td>
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
                {totalContactCount} Total Results
              </p>
            </div>
            <div className='flex flex-wrap items-center gap-3'>
              <label>Showing</label>
              <select defaultValue={contactPageSize} className='border rounded py-1' onChange={(e) => {
                setCurrentContactPage(1)
                setContactPageSize(e.target.value)
              }}>
                <option>1</option>
                <option>5</option>
                <option>10</option>
                <option>20</option>
              </select>
              <nav className="isolate inline-flex -space-x-px rounded-md shadow-sm" aria-label="Pagination">
                <button
                  disabled={currentContactPage === 1}
                  onClick={() => {
                    setCurrentContactPage(currentContactPage - 1)
                  }} className="relative inline-flex items-center rounded-l-md px-2 py-2 text-gray-400 ring-1 ring-inset ring-gray-300 hover:bg-gray-50  focus:outline-offset-0">
                  <span className="sr-only">Previous</span>
                  <svg className="h-5 w-5" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                    <path fillRule="evenodd" d="M12.79 5.23a.75.75 0 01-.02 1.06L8.832 10l3.938 3.71a.75.75 0 11-1.04 1.08l-4.5-4.25a.75.75 0 010-1.08l4.5-4.25a.75.75 0 011.06.02z" clipRule="evenodd" />
                  </svg>
                </button>

                <p className="relative inline-flex items-center px-4 py-2 text-sm font-semibold text-gray-900 ring-1 ring-inset ring-gray-300 hover:bg-gray-50  focus:outline-offset-0">
                  Page {currentContactPage} of {totalContactPage}
                </p>

                <button
                  disabled={currentContactPage === totalContactPage}
                  onClick={() => {
                    setCurrentContactPage(currentContactPage + 1)
                  }} className="relative inline-flex items-center rounded-r-md px-2 py-2 text-gray-400 ring-1 ring-inset ring-gray-300 hover:bg-gray-50  focus:outline-offset-0">
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

    </div>

  )
}

export default AdminContact