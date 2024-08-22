import React from 'react'
import { FaArrowRight } from 'react-icons/fa'
import { Link } from 'react-router-dom'

function GetStarted() {
    return (
        <div className='bg-secondary p-5 py-28'>
            {/* <h1 className='text-center text-4xl font-semibold'>Explore cars for every occasion</h1> */}
            <div className='grid md:grid-cols-2 max-w-7xl mx-auto items-center justify-between gap-10'>
                <div className='p-5'>
                    <img src='/getstarted1.png' className='mx-auto' />
                </div>
                <div className='flex flex-col gap-4 lg:px-20 px-5'>
                    <h3 className='text-4xl font-semibold'>Explore cars for every occasion</h3>
                    <h3 className=''>From luxury sedans to rugged SUVs, find the ideal car for any occasion. Our extensive fleet is available for short-term and long-term rentals, ensuring you have the right vehicle at the right time. Explore our options and start your adventure today.</h3>
                    <Link to={'/explore'} className='btn-primary max-w-fit'>Explore</Link>
                </div>
            </div>
        </div>
    )
}

export default GetStarted