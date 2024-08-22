import React from 'react'
import { BsFacebook, BsInstagram, BsLinkedin, BsTwitter, BsYoutube } from 'react-icons/bs'
import { Link } from 'react-router-dom'

function Footer() {
    return (
        <footer className="bg-blue-700  py-10 shadow  ">
            <div className="w-full max-w-screen-xl mx-auto p-4 md:py-8">
                <div className="grid grid-cols-6 items-start">
                    <ul className='sm:col-span-3 col-span-full items-start text-white sm:mb-0 mb-10'>
                        <p className=''> <b className='text-xl mb-2'>Go Ride</b> <br />Drive Your Adventure</p>
                        <a href="/" className="grid items-center mb-4 sm:mb-0 space-x-3 rtl:space-x-reverse my-3">
                            <img src="/app_logo.png" className="h-24 bg-white" alt="goride" />
                        </a>
                    </ul>

                    <ul className="grid sm:col-span-1 col-span-3 items-center gap-3 mb-6 text-sm font-medium text-gray-300 sm:mb-0 ">
                        <li className='mb-5 text-white'>
                            <label className=" me-4 md:me-6">Company</label>
                        </li>
                        <li>
                            <a href="/" className="hover:underline me-4 md:me-6">Home</a>
                        </li>
                        <li>
                            <a href="/#" className="hover:underline">About Us</a>
                        </li>
                        <li>
                            <a href="/#" className="hover:underline">Services</a>
                        </li>
                        <li>
                            <a href="/contact" className="hover:underline">Contact</a>
                        </li>
                    </ul>
                    <ul className="grid sm:col-span-1 col-span-3 items-center gap-3 mb-6 text-sm font-medium text-gray-300 sm:mb-0 ">
                        <li className='mb-5'>
                            <label className=" me-4 md:me-6 text-white">Contact Us</label>
                        </li>
                        <li>
                            <a href="/forum" className="hover:underline me-4 md:me-6">Kathmandu, Nepal</a>
                        </li>
                        <li>
                            <a href="/blogs" className="hover:underline me-4 md:me-6">123456789</a>
                        </li>
                        <li>
                            <a href="/contact" className="hover:underline">goride@gmail.com</a>
                        </li>
                    </ul>
                    <ul className="grid sm:col-span-1 col-span-3 items-center gap-3 mb-6 text-sm font-medium text-gray-500 sm:mb-0 ">
                        <div className='flex gap-3 mt-5 text-white'>
                            <Link to={'/https://www.instagram.com/starstv/'} target='blank' className='border p-2 rounded-full'>
                                <BsInstagram />
                            </Link>
                            <Link to={'/https://www.facebook.com/aussiestarstv/'} target='blank' className='border p-2 rounded-full'>
                                <BsFacebook />
                            </Link>
                            <Link to={'https://www.youtube.com/user/clubSTARStv'} target='blank' className='border p-2 rounded-full'>
                                <BsYoutube />
                            </Link>
                        </div>
                    </ul>
                </div>
                <hr className="my-6 border-gray-200 sm:mx-auto text-white lg:my-8" />
                <div className='flex justify-between flex-wrap'>
                    <span className="block text-sm text-white sm:text-center ">© Copyright 2024 <a href="/" className="hover:underline">Go Ride</a>. All Rights Reserved.</span>
                    <span className="block text-sm text-white sm:text-center ">Designed By Ashutosh Aryal.</span>
                </div>
            </div>
        </footer>
    )
}

export default Footer