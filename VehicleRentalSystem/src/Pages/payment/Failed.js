import React from 'react'
import { FaRegTimesCircle } from 'react-icons/fa'
import { Link } from 'react-router-dom'

function Failed() {
  return (
    <div className='h-96 text-center grid place-items-center'>
    <div className='w-fit h-fit flex flex-col mx-auto text-center'>
        <FaRegTimesCircle color='red' className='mx-auto' size={50} />
        <p className='mt-4'>
            Your Payment has Failed
        </p>
        <Link to={"/profile"} className='p-2 rounded btn-primary px-4 w-fit mx-auto'>Go To Profile</Link>
    </div>
</div>
  )
}

export default Failed