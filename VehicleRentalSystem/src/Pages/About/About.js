import React from 'react'

function About() {
    return (
        <div className='max-w-7xl mx-auto py-10 px-5 mb-10'>

            <section className="py-14 lg:py-24 relative z-0 bg-gray-50">
                <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 relative text-center">
                    <h1
                        className="max-w-2xl mx-auto text-center font-manrope font-bold text-4xl  text-gray-900 mb-5 md:text-5xl md:leading-normal">
                        Find or Rent Vehicles with <span className="text-indigo-600">Go Ride </span>
                    </h1>
                    <p className="max-w-sm mx-auto text-center text-base font-normal leading-7 text-gray-500 mb-9">
                        Discover a better way to rent or find vehicles.
                    </p>
                </div>
            </section>

            <section className="py-14 lg:py-24 relative">
                <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 relative ">
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-9">
                        <div className="img-box">
                            <img src="/app_logo.png" alt="About Us tailwind page"
                                className="max-lg:mx-auto h-full w-full" />
                        </div>
                        <div className="lg:pl-[100px] flex items-center">
                            <div className="data w-full">
                                <h2
                                    className="font-manrope font-bold text-4xl lg:text-5xl text-black mb-9 max-lg:text-center relative">
                                    About
                                    Us </h2>
                                <p className="font-normal text-xl leading-8 text-gray-500 max-lg:text-center max-w-2xl mx-auto">
                                    Fueled by a commitment to exceptional mobility solutions, we've carefully crafted our vehicle rental system to serve travelers, businesses, and everyday commuters. Our mission is to offer a versatile platform that provides easy access to a wide range of vehicles, ensuring convenience, reliability, and satisfaction at every journey's start.
                                </p>
                            </div>
                        </div>
                    </div>
                </div>
            </section>

            <section className="py-14 lg:py-24 relative">
                <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 relative ">
                    <div className="grid grid-cols-1 lg:grid-cols-2 lg:gap-9 ">

                        <div className="lg:pr-24 flex items-center">
                            <div className="data w-full">
                                <img src="/handshake.png" alt="About Us tailwind page"
                                    className="block lg:hidden h-full w-full mb-9 mx-auto" />
                                <h2 className="font-manrope font-bold text-4xl lg:text-5xl text-black mb-9 max-lg:text-center">
                                    
                                </h2>
                                <p className="font-normal text-xl leading-8 text-gray-500 max-lg:text-center max-w-2xl mx-auto">
                                    Go Ride isn’t just a simple vehicle rental service. We go beyond merely providing vehicles, emphasizing accessibility, reliability, and convenience. Every feature, from the smallest detail to the overall rental experience, is thoughtfully designed to enhance functionality and elevate customer satisfaction.
                                </p>
                            </div>
                        </div>
                        <div className="img-box ">
                            <img src="/handshake.png" alt="About Us tailwind page"
                                className="hidden h-full w-full lg:block " />
                        </div>
                    </div>
                </div>
            </section>

            <section className="py-20 bg-white">
                <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
                    <h2 className="font-manrope text-4xl text-center text-gray-900 font-bold mb-14">Our results in numbers</h2>
                    <div className="flex flex-col gap-5 xl:gap-8 lg:flex-row lg:justify-between">
                        <div
                            className="w-full max-lg:max-w-2xl mx-auto lg:mx-0 lg:w-1/3 bg-white p-6 rounded-2xl shadow-md shadow-gray-100">
                            <div className="flex gap-5">
                                <div className="font-manrope text-2xl font-bold text-indigo-600">
                                    100+
                                </div>
                                <div className="flex-1">
                                    <h4 className="text-xl text-gray-900 font-semibold mb-2">Total Vehicles</h4>
                                    <p className="text-xs text-gray-500 leading-5">Company's remarkable growth journey as we
                                        continually innovate and drive towards new heights of success.</p>
                                </div>
                            </div>
                        </div>
                        <div
                            className="w-full max-lg:max-w-2xl mx-auto lg:mx-0 lg:w-1/3 bg-white p-6 rounded-2xl shadow-md shadow-gray-100">
                            <div className="flex gap-5">
                                <div className="font-manrope text-2xl font-bold text-indigo-600">
                                    175+
                                </div>
                                <div className="flex-1">
                                    <h4 className="text-xl text-gray-900 font-semibold mb-2">Users</h4>
                                    <p className="text-xs text-gray-500 leading-5">With over 175 users who trust and use our system, Go Ride stands as a testament to reliability and customer satisfaction. </p>
                                </div>
                            </div>
                        </div>
                        <div
                            className="w-full max-lg:max-w-2xl mx-auto lg:mx-0 lg:w-1/3 bg-white p-6 rounded-2xl shadow-md shadow-gray-100">
                            <div className="flex gap-5">
                                <div className="font-manrope text-2xl font-bold text-indigo-600">
                                    625
                                </div>
                                <div className="flex-1">
                                    <h4 className="text-xl text-gray-900 font-semibold mb-2">Orders</h4>
                                    <p className="text-xs text-gray-500 leading-5">We have accomplished more than 625 orders
                                        nation wide and we are still counting many more.</p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </section>
        </div>
    )
}

export default About