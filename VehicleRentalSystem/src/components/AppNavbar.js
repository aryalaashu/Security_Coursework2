import React, { useContext, useEffect, useState } from 'react';
import { AuthContext } from '../context/authContext';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import axios from '../axios';
import { MdArrowBackIos, MdOutlineMenu, MdOutlineShoppingBag } from 'react-icons/md'
import { GoBell, GoHeart, GoSearch } from 'react-icons/go'
import { FaBars } from 'react-icons/fa'
import SideNav from './SideNav';
import { FaHamburger, FaThumbsUp } from 'react-icons/fa'
import { MdClose } from 'react-icons/md'
import toast from 'react-hot-toast';
import { BsBell } from 'react-icons/bs';

const AppNavbar = () => {
    const { isAuthenticated, userDetails } = useContext(AuthContext);
    const navigate = useNavigate();
    const location = useLocation();
    const [keyword, setKeyword] = useState('')

    const [toggleNav, setToggleNav] = useState(true);
    const [notificationModal, setNotificationModal] = useState(false);
    const [sideNav, setSideNav] = useState(false);
    const [categoryData, setCategoryData] = useState([])

    const navigation = [
        { name: 'home', href: '/' },
        { name: 'About Us', href: '/about' },
        { name: 'services', href: '/services' },
        { name: 'contact us', href: '/contact' },
    ]
    const authnavigation = [
        { name: 'home', href: '/' },
        { name: 'My Rentals', href: '/my-rentals' },
        { name: 'Become a Host', href: '/become-a-host' },
        { name: 'contact us', href: '/contact' },
    ]

    const scrollToTop = () => {
        window.scrollTo({
            top: 0,
            behavior: "smooth", // for smoothly scrolling
        });
    };

    const notificationHandler = () => {
        setNotificationModal(!notificationModal);
    };

    const handleNav = () => {
        setToggleNav(!toggleNav);
    };

    const [navbackground, setNavBackground] = useState(false);

    const changenavbackground = () => {
        if (window.scrollY >= 30) {
            setNavBackground(true);
        } else {
            setNavBackground(false);
        }
    };

    window.addEventListener("scroll", changenavbackground);

    const handelNotification = () => {
        if (notificationModal) setNotificationModal(false);
    };

    const logout = () => {
        localStorage.removeItem("_hw_token");
        localStorage.removeItem("_hw_userDetails");

        setTimeout(() => {
            window.location.href = "/login"
        }, 400)
    };

    const [mobileMenuOpen, setMobileMenuOpen] = useState(false)

    const searchFunction = () => {
        navigate('/product', {
            state: {
                search: keyword
            }
        })
    } 

    return (
        <div
            className={`transition ease-in z-30 sticky top-0 duration-300 hover:bg-white ${navbackground && "bg-white"
                } ${location.pathname === '/login' && 'hidden'} ${location.pathname === '/signup' && 'hidden'} ${location.pathname.includes('dashboard') && 'hidden'}`}
            onClick={handelNotification}
        >
            <header className={` inset-x-0 top-0 z-50 ${navbackground ? "bg-white" : "bg-transparent"}`}>
                <nav className="flex items-center justify-between p-2 lg:px-8" aria-label="Global">
                    <div className="flex lg:flex-1">
                        <a href="/" className="p-1.5">
                            <img
                                className=" w-32"
                                src="/app_logo.png"
                                alt="applog"
                            />
                            {/* <span className="font-bold text-xl">goride</span> */}
                        </a>
                    </div>
                    <div className="flex lg:hidden">
                        <button
                            type="button"
                            className="-m-2.5 inline-flex items-center justify-center rounded-md p-2.5 text-gray-700"
                            onClick={() => setMobileMenuOpen(true)}
                        >
                            <span className="sr-only">Open main menu</span>
                            <FaBars className="h-6 w-6" aria-hidden="true" />
                        </button>
                    </div>
                    <div className="hidden lg:flex lg:gap-x-12 ">
                        {isAuthenticated ? authnavigation.map((item, index) => (
                            <div role='button' key={index} onClick={() => {
                                if (!item.children) {
                                    navigate(item.href)
                                }
                            }} href={item.href} className={`relative capitalize font-semibold text-sm group hover:border-b-blue-700 px-3 hover:border-b-2 border-b-2 border-transparent py-2 ${location.pathname === item.href &&
                                "text-blue-700 "
                                }`}>
                                {item.name}
                                {
                                    item.children &&
                                    <div className='hidden group-hover:block absolute pt-5 w-[150px] left-0'>
                                        <ul>
                                            {
                                                item.children.map((value, index) => (
                                                    <li key={index} onClick={() => {
                                                        navigate('/product', { state: { category: value._id } });
                                                    }} role='button' className='p-2 border hover:bg-gray-50 bg-white capitalize'>{value.name}</li>
                                                ))}
                                        </ul>

                                    </div>

                                }
                            </div>
                        )) : navigation.map((item, index) => (
                            <div role='button' key={index} onClick={() => {
                                if (!item.children) {
                                    navigate(item.href)
                                }
                            }} href={item.href} className={`relative capitalize font-semibold text-sm group hover:border-b-blue-700 px-3 hover:border-b-2 border-b-2 border-transparent py-2 ${location.pathname === item.href &&
                                "text-blue-700 "
                                }`}>
                                {item.name}
                                {
                                    item.children &&
                                    <div className='hidden group-hover:block absolute pt-5 w-[150px] left-0'>
                                        <ul>
                                            {
                                                item.children.map((value, index) => (
                                                    <li key={index} onClick={() => {
                                                        navigate('/product', { state: { category: value._id } });
                                                    }} role='button' className='p-2 border hover:bg-gray-50 bg-white capitalize'>{value.name}</li>
                                                ))}
                                        </ul>

                                    </div>

                                }
                            </div>
                        ))}
                    </div>
                    <div className="hidden lg:flex lg:flex-1 lg:justify-end gap-5">
                        <div className="flex items-center gap-3">
                            {/* {
                                isAuthenticated &&
                                <Link to={"/notices"}>
                                    <button className=" py-2 px-2 text-sm hover:bg-blue-200 duration-150 hover:scale-105 rounded-lg">
                                        <BsBell size={20} />
                                    </button>
                                </Link>
                            } */}
                            {/* <div className="  cursor-pointer ">
                                <Link to={"/login"}>
                                    <button className="bg-current py-2 text-white px-6 text-sm hover:bg-blue-200 duration-150 hover:scale-105 rounded-lg">
                                        Login
                                    </button>
                                </Link>
                            </div> */}

                            {isAuthenticated ? (
                                <div className="flex items-center ml-4">
                                    <div className="flex">
                                        <span className="group relative inline-block">
                                            <button
                                                type="button"
                                                className="flex items-center mr-3 text-sm md:mr-0 h-full cursor-pointer"
                                                id="user-menu-button"
                                                data-dropdown-toggle="dropdown"
                                            >
                                                <div className=" overflow-hidden rounded-full">
                                                    {userDetails?.image ? (
                                                        <img
                                                            className="w-7 rounded-full object-cover object-center sm:w-8 md:w-8 h-7"
                                                            src={`${process.env.REACT_APP_IMG_URI}${userDetails?.image}`}
                                                            alt="user photo"
                                                        />
                                                    ) : (
                                                        <img
                                                            className="w-7 rounded-full object-cover object-center sm:w-8 md:w-7 h-7 border"
                                                            src="/defaultUserImage.png"
                                                            alt="user photo"
                                                        />
                                                    )}
                                                </div>

                                            </button>

                                            <ul className="absolute right-0 hidden pt-1 w-40 p-2 border rounded bg-white text-gray-700 group-hover:block">
                                                <Link to={"/profile"}>
                                                    <li className="cursor-pointer text-gray-600 text-sm leading-3 tracking-normal py-2 hover:text-indigo-700 focus:text-indigo-700 focus:outline-none">
                                                        <div className="flex items-center">
                                                            <svg
                                                                xmlns="http://www.w3.org/2000/svg"
                                                                className="icon icon-tabler icon-tabler-user"
                                                                width={20}
                                                                height={20}
                                                                viewBox="0 0 24 24"
                                                                strokeWidth={2}
                                                                stroke="currentColor"
                                                                fill="none"
                                                                strokeLinecap="round"
                                                                strokeLinejoin="round"
                                                            >
                                                                <path stroke="none" d="M0 0h24v24H0z" />
                                                                <circle cx={12} cy={7} r={4} />
                                                                <path d="M6 21v-2a4 4 0 0 1 4 -4h4a4 4 0 0 1 4 4v2" />
                                                            </svg>
                                                            <span className="ml-2">My Profile</span>
                                                        </div>
                                                    </li>
                                                </Link>
                                                <li
                                                    onClick={() => logout()}
                                                    className="cursor-pointer text-gray-600 text-sm leading-3 tracking-normal mt-2 py-2 hover:text-indigo-700 focus:text-indigo-700 focus:outline-none flex items-center"
                                                >
                                                    <svg
                                                        xmlns="http://www.w3.org/2000/svg"
                                                        className="h-5 w-6"
                                                        fill="none"
                                                        viewBox="0 0 24 24"
                                                        stroke="currentColor"
                                                    >
                                                        <path
                                                            strokeLinecap="round"
                                                            strokeLinejoin="round"
                                                            strokeWidth="2"
                                                            d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"
                                                        />
                                                    </svg>
                                                    <span className="ml-2">Log Out</span>
                                                </li>
                                            </ul>
                                        </span>
                                    </div>
                                </div>
                            ) : (
                                <div className="flex gap-2 mr-2 ml-5 ">
                                    <div className="cursor-pointer ">
                                        <Link to={"/login"}>
                                            <button className="bg-current py-2 text-white px-6 text-sm hover:bg-blue-200 duration-150 hover:scale-105 rounded-lg">
                                                Login
                                            </button>
                                        </Link>
                                    </div>

                                    {/* <div className="  cursor-pointer ">
                                        <Link to={"/signup"}>
                                            <button className="px-4 py-2 border text-sm hover:bg-blue-200 duration-150 hover:scale-105 rounded-full">
                                                Sign Up
                                            </button>
                                        </Link>
                                    </div> */}
                                </div>
                            )}

                        </div>
                    </div>
                </nav>
                {
                    mobileMenuOpen &&
                    <div className="lg:hidden" open={mobileMenuOpen} onClose={setMobileMenuOpen}>
                        <div className="fixed inset-0 z-50" />
                        <div className="fixed inset-y-0 right-0 z-50 w-full overflow-y-auto bg-white px-6 py-6 sm:max-w-sm sm:ring-1 sm:ring-gray-900/10">
                            <div className="flex items-center justify-between">
                                <a href="/" className="-m-1.5 p-1.5">
                                    <span className="sr-only">goride</span>
                                    <img
                                        className="h-8 w-auto"
                                        src="/app_logo.png"
                                        alt="applogo"
                                    />
                                </a>
                                <button
                                    type="button"
                                    className="-m-2.5 rounded-md p-2.5 text-gray-700"
                                    onClick={() => setMobileMenuOpen(false)}
                                >
                                    <span className="sr-only">Close menu</span>
                                    <MdClose className="h-6 w-6" aria-hidden="true" />
                                </button>
                            </div>


                            <div className="mt-6 flow-root">
                                <div className="-my-6 divide-y divide-gray-500/10">
                                    <div className="space-y-2 py-6">
                                        {isAuthenticated ? authnavigation.map((item, index) => (
                                            <a
                                                key={index}
                                                href={item.href}
                                                className="-mx-3 capitalize block rounded-lg px-3 py-2 text-base font-semibold leading-7 text-gray-900 hover:bg-gray-50"
                                            >
                                                {item.name}
                                            </a>
                                        )) : navigation.map((item, index) => (
                                            <a
                                                key={index}
                                                href={item.href}
                                                className="-mx-3 capitalize block rounded-lg px-3 py-2 text-base font-semibold leading-7 text-gray-900 hover:bg-gray-50"
                                            >
                                                {item.name}
                                            </a>
                                        ))}
                                    </div>

                                    <div className="py-2 flex items-center justify-between">

                                        <div className="  cursor-pointer ">
                                            <Link to={"/contact"}>
                                                <button
                                                    // className="bg-current py-2 text-white px-6 text-sm hover:bg-blue-200 duration-150 hover:scale-105 rounded-lg"
                                                    className="-mx-3 capitalize block rounded-lg px-3 py-2 text-base font-semibold leading-7 text-gray-900 hover:bg-gray-50"
                                                >
                                                    Contact
                                                </button>
                                            </Link>
                                        </div>

                                        {/* {
                                            isAuthenticated &&
                                            <Link to={"/notices"}>
                                                <button className=" py-2 px-2 text-sm hover:bg-blue-200 duration-150 hover:scale-105 rounded-lg">
                                                    <BsBell size={20} />
                                                </button>
                                            </Link>
                                        } */}
                                        {isAuthenticated ? (
                                            <div className="group relative inline-block">
                                                <button
                                                    type="button"
                                                    className="flex items-center mr-3 text-sm md:mr-0 h-full cursor-pointer"
                                                    id="user-menu-button"
                                                    data-dropdown-toggle="dropdown"
                                                >
                                                    <div className=" overflow-hidden rounded-full">
                                                        {userDetails?.image ? (
                                                            <img
                                                                className="w-7 rounded-full object-cover object-center sm:w-8 md:w-8 h-7"
                                                                src={`${process.env.REACT_APP_IMG_URI}${userDetails?.image}`}
                                                                alt="user photo"
                                                            />
                                                        ) : (
                                                            <img
                                                                className="w-7 rounded-full object-cover object-center sm:w-8 md:w-7 h-7 border"
                                                                src="/defaultUserImage.png"
                                                                alt="user photo"
                                                            />
                                                        )}
                                                    </div>

                                                </button>

                                                <ul className="absolute right-0 hidden pt-1 w-40 p-2 border rounded bg-white text-gray-700 group-hover:block">
                                                    <Link to={"/profile"}>
                                                        <li className="cursor-pointer text-gray-600 text-sm leading-3 tracking-normal py-2 hover:text-indigo-700 focus:text-indigo-700 focus:outline-none">
                                                            <div className="flex items-center">
                                                                <svg
                                                                    xmlns="http://www.w3.org/2000/svg"
                                                                    className="icon icon-tabler icon-tabler-user"
                                                                    width={20}
                                                                    height={20}
                                                                    viewBox="0 0 24 24"
                                                                    strokeWidth={2}
                                                                    stroke="currentColor"
                                                                    fill="none"
                                                                    strokeLinecap="round"
                                                                    strokeLinejoin="round"
                                                                >
                                                                    <path stroke="none" d="M0 0h24v24H0z" />
                                                                    <circle cx={12} cy={7} r={4} />
                                                                    <path d="M6 21v-2a4 4 0 0 1 4 -4h4a4 4 0 0 1 4 4v2" />
                                                                </svg>
                                                                <span className="ml-2">My Profile</span>
                                                            </div>
                                                        </li>
                                                    </Link>
                                                    <li
                                                        onClick={() => logout()}
                                                        className="cursor-pointer text-gray-600 text-sm leading-3 tracking-normal mt-2 py-2 hover:text-indigo-700 focus:text-indigo-700 focus:outline-none flex items-center"
                                                    >
                                                        <svg
                                                            xmlns="http://www.w3.org/2000/svg"
                                                            className="h-5 w-6"
                                                            fill="none"
                                                            viewBox="0 0 24 24"
                                                            stroke="currentColor"
                                                        >
                                                            <path
                                                                strokeLinecap="round"
                                                                strokeLinejoin="round"
                                                                strokeWidth="2"
                                                                d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"
                                                            />
                                                        </svg>
                                                        <span className="ml-2">Log Out</span>
                                                    </li>
                                                </ul>
                                            </div>
                                        ) : (
                                            <div className="py-6 w-full">
                                                <a
                                                    href={"/signup"}
                                                    className="-mx-3 block rounded-lg px-3 py-2.5 text-base font-semibold leading-7 text-gray-900 hover:bg-gray-50"
                                                >
                                                    Sign Up
                                                </a>
                                                <Link
                                                    to={"/login"}
                                                    onClick={() => {
                                                        setMobileMenuOpen(false)
                                                    }}
                                                    className="-mx-3 block rounded-lg px-3 py-2.5 text-base font-semibold leading-7 text-gray-900 hover:bg-gray-50"
                                                >
                                                    Log in
                                                </Link>
                                            </div>
                                        )}

                                    </div>


                                </div>
                            </div>
                        </div>
                    </div>
                }
            </header>

        </div>
    );
}

export default AppNavbar;
