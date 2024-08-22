import React from 'react'
import { FaArrowRight } from 'react-icons/fa';
import { Link } from 'react-router-dom';

function HeroSection() {
    return (
        <div className='grid md:grid-cols-2 items-center mx-auto p-10'>
            <div className='flex flex-col justify-center justify-items-center items-start max-w-xl mx-auto gap-4 h-72'>
                <h1 className='xl:text-6xl text-4xl font-bold'>Go Ride
                    Drive Your Adventure</h1>
                <h2 className=''>Discover the freedom of the open road with Go Ride. Whether you need a vehicle for a weekend getaway, a business trip, or simply to explore the city, we have the perfect ride for you. Our platform offers a wide selection of two-wheelers and four-wheelers to suit your needs. Experience convenience and reliability with every journey.</h2>
                <Link
                    to={'/'}
                    className='bg-current p-3 px-6 rounded text-white mt-4 flex gap-6 items-center'>Explore
                    {/* <FaArrowRight />  */}
                </Link>
            </div>
            <div>
                <img className='w-full' src='/heroimg1.png' />
            </div>
        </div>
    )
}

export default HeroSection