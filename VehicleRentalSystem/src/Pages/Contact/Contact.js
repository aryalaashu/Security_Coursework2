import { useState } from 'react'
import axios from '../../axios'
import { Field, Form, Formik } from 'formik'
import toast from 'react-hot-toast'
import { CgMail } from 'react-icons/cg'
import { FaLocationDot, FaLocationPin } from 'react-icons/fa6'
import { HiPhone } from 'react-icons/hi'
import ReCAPTCHA from 'react-google-recaptcha';

function Contact() {

    const [expandedIndex, setExpandedIndex] = useState(null)
    const [recaptcha, setRecaptcha] = useState(null);


    const handleFormSubmit = async (values, actions) => {
        if (!recaptcha) {
            toast.error('Please complete the reCAPTCHA');
            return;
          }
      
        try {
            const token = await recaptcha.executeAsync();
            let result = await axios.post('/contact', {...values,recaptchaToken: token})

            if (result.data.success) {
                toast.success('Message Submitted Successfully')
                setTimeout(() => {
                    window.location.reload()
                }, 1000)
            } else toast.error('Failed')
        } catch (ERR) {
            console.log(ERR)
            toast.error(ERR.response.data.msg)
        }
    }


    return (
        <>
            <div className="mx-auto  relative overflow-hidden">
                <img src='./contactbg.png' className='w-full h-72 object-cover' />
                <div className='absolute top-1/2 left-10 -translate-y-1/2 text-white w-full'>
                    <div className='max-w-6xl mx-auto'>
                        <h2 className="text-3xl font-bold tracking-tight sm:text-4xl">Contact Us</h2>
                    </div>
                </div>
            </div>
            <div className='flex py-10 justify-center divide-x-2 divide-gray-400 gap-4'>
                <div className="isolate  px-6 pb-10">
                    <Formik
                        enableReinitialize
                        initialValues={{
                            name: "",
                            email: "",
                            mobile_no: "",
                            message: "",
                        }}
                        onSubmit={(values, actions) => {
                            handleFormSubmit(values, actions);
                        }}>

                        {
                            (props) => (
                                <Form className="mx-auto max-w-xl  ">
                                    <p className='mb-10'>Contact us about anything related to our company or services. We’ll do our best to get back to you as soon as possible.</p>

                                    <div className="grid grid-cols-1 gap-x-8 gap-y-6 sm:grid-cols-2">
                                        <div className='col-span-full'>
                                            <label htmlFor="name" className="block text-sm font-semibold leading-6 text-gray-900">
                                                Name
                                            </label>
                                            <div className="mt-2.5">
                                                <Field
                                                    required
                                                    type="text"
                                                    name="name"
                                                    id="name"
                                                    autoComplete="given-name"
                                                    className="block w-full rounded-md border-0 px-3.5 py-2 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"
                                                />
                                            </div>
                                        </div>

                                        <div className="sm:col-span-2">
                                            <label htmlFor="email" className="block text-sm font-semibold leading-6 text-gray-900">
                                                Email
                                            </label>
                                            <div className="mt-2.5">
                                                <Field
                                                    required
                                                    type="email"
                                                    name="email"
                                                    id="email"
                                                    autoComplete="email"
                                                    className="block w-full rounded-md border-0 px-3.5 py-2 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"
                                                />
                                            </div>
                                        </div>
                                        <div className="sm:col-span-2">
                                            <label htmlFor="mobile_no" className="block text-sm font-semibold leading-6 text-gray-900">
                                                Phone number
                                            </label>
                                            <div className="relative mt-2.5">
                                                <div className="absolute inset-y-0 left-0 flex items-center">
                                                    <label htmlFor="country" className="sr-only">
                                                        Country Code
                                                    </label>
                                                    <p
                                                        disabled
                                                        id="country"
                                                        name="country"
                                                        className="h-full rounded-md border-0 bg-transparent bg-none py-2.5 pl-4 pr-1 text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm"
                                                    >
                                                        +977
                                                    </p>
                                                </div>
                                                <Field
                                                    required
                                                    type="tel"
                                                    name="mobile_no"
                                                    id="mobile_no"
                                                    autoComplete="tel"
                                                    className="block w-full rounded-md border-0 px-3.5 py-2 pl-14 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"
                                                />
                                            </div>
                                        </div>
                                        <div className="sm:col-span-2">
                                            <label htmlFor="message" className="block text-sm font-semibold leading-6 text-gray-900">
                                                Message
                                            </label>
                                            <div className="mt-2.5">
                                                <Field
                                                    required
                                                    as="textarea"
                                                    name="message"
                                                    id="message"
                                                    rows={4}
                                                    className="block w-full rounded-md border-0 px-3.5 py-2 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"
                                                    defaultValue={''}
                                                />
                                            </div>
                                        </div>

                  <div className="mt-6  w-full">
                    <ReCAPTCHA
                      sitekey="6Ld5_CoqAAAAAOy3WS3NLMssRnPHABtCvw9NYJpX"  // Replace with your reCAPTCHA v3 Site Key
                      size="invisible"
                      ref={(el) => setRecaptcha(el)}
                    />
                  </div>

                                    </div>
                                    <div className="mt-10">
                                        <button
                                            type="submit"
                                            className="block w-full rounded-md bg-indigo-600 px-3.5 py-2.5 text-center text-sm font-semibold text-white shadow-sm hover:bg-indigo-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-600"
                                        >
                                            Submit
                                        </button>
                                    </div>
                                </Form>
                            )
                        }
                    </Formik>
                </div>
                <div className="isolate  px-6  lg:px-8">
                    <img src='./contact1.png' />
                    <div className='text-center md:text-2xl mt-4'> <p><b className=''>GO RIDE</b><br />Drive Your Adventure</p></div>

                    <ul className='mt-4'>
                        <li className='flex items-center justify-center gap-3 md:text-xl text-sm'> <span><FaLocationDot color='blue' size={20} /></span>  Kathmandu Nepal</li>
                        <li className='flex items-center justify-center gap-3 md:text-xl text-sm'> <span><HiPhone color='blue' size={20} /></span>  +977-9000000075</li>
                        <li className='flex items-center justify-center gap-3 md:text-xl text-sm'> <span><CgMail color='blue' size={20} /></span>  goride@gmail.com</li>
                    </ul>
                </div>

            </div>

            <section className="py-24">
                <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
                    <div className="mb-16">
                        <h6 className="text-lg text-indigo-600 font-medium text-center mb-2">
                            FAQs
                        </h6>
                        <h2
                            className="text-4xl font-manrope text-center font-bold text-gray-900 leading-[3.25rem]"
                        >
                            Frequently asked questions
                        </h2>
                    </div>

                    <div className="accordion-group" data-accordion="default-accordion">
                        <div
                            className="accordion py-8 px-6 border-b border-solid border-gray-200 transition-all duration-500 rounded-2xl hover:bg-indigo-50 accordion-active:bg-indigo-50 active"
                            id="basic-heading-one-with-arrow"
                        >
                            <button
                                onClick={() => {
                                    setExpandedIndex(0)
                                }}
                                className="accordion-toggle group inline-flex items-center justify-between leading-8 text-gray-900 w-full transition duration-500 text-left hover:text-indigo-600 accordion-active:font-medium "
                                aria-controls="basic-collapse-one-with-arrow"
                            >
                                <h5>How do I update my billing information?</h5>
                                <svg
                                    className={`text-gray-500 transition duration-500 group-hover:text-indigo-600   ${expandedIndex === 0 ? "rotate-180" : ""}`}
                                    width="22"
                                    height="22"
                                    viewBox="0 0 22 22"
                                    fill="none"
                                    xmlns="http://www.w3.org/2000/svg"
                                >
                                    <path
                                        d="M16.5 8.25L12.4142 12.3358C11.7475 13.0025 11.4142 13.3358 11 13.3358C10.5858 13.3358 10.2525 13.0025 9.58579 12.3358L5.5 8.25"
                                        stroke="currentColor"
                                        stroke-width="1.6"
                                        stroke-linecap="round"
                                        stroke-linejoin="round"
                                    ></path>
                                </svg>
                            </button>
                            <div
                                id="basic-collapse-one-with-arrow"
                                className={`w-full px-0 overflow-hidden ${expandedIndex === 0 ? "" : "h-0"} ease-in`}
                                aria-labelledby="basic-heading-one-with-arrow"
                            >
                                <p className="text-base text-gray-900 leading-6">
                                    To contact customer support, look for a 'Contact us' or 'Help'
                                    button or link on the website or platform. You may be able to
                                    email, call, or chat with customer support for assistance.
                                </p>
                            </div>
                        </div>
                        <div
                            className="accordion py-8 px-6 border-b border-solid border-gray-200 transition-all duration-500 rounded-2xl hover:bg-indigo-50 accordion-active:bg-indigo-50"
                            id="basic-heading-two-with-arrow"
                        >
                            <button
                                onClick={() => {
                                    setExpandedIndex(1)
                                }}
                                className="accordion-toggle group inline-flex items-center justify-between leading-8 text-gray-900 w-full transition duration-500 text-left hover:text-indigo-600 "
                                aria-controls="basic-collapse-two-with-arrow"
                            >
                                <h5>Can I extend my rental period?</h5>
                                <svg
                                    className={`text-gray-500 transition duration-500 group-hover:text-indigo-600   ${expandedIndex === 1 ? "rotate-180" : ""}`}
                                    width="22"
                                    height="22"
                                    viewBox="0 0 22 22"
                                    fill="none"
                                    xmlns="http://www.w3.org/2000/svg"
                                >
                                    <path
                                        d="M16.5 8.25L12.4142 12.3358C11.7475 13.0025 11.4142 13.3358 11 13.3358C10.5858 13.3358 10.2525 13.0025 9.58579 12.3358L5.5 8.25"
                                        stroke="currentColor"
                                        stroke-width="1.6"
                                        stroke-linecap="round"
                                        stroke-linejoin="round"
                                    ></path>
                                </svg>
                            </button>
                            <div
                                id="basic-collapse-two-with-arrow"
                                className={`w-full px-0 overflow-hidden ${expandedIndex === 1 ? "" : "h-0"} ease-in`}
                                aria-labelledby="basic-heading-two-with-arrow"
                            >
                                <p className="text-base text-gray-900 leading-6">
                                If you need to extend your rental, please contact the vehicle owner as soon as possible. Extensions are subject to vehicle availability and additional charges.
                                </p>
                            </div>
                        </div>
                        <div
                            className="accordion py-8 px-6 border-b border-solid border-gray-200 transition-all duration-500 rounded-2xl hover:bg-indigo-50 accordion-active:bg-indigo-50"
                            id="basic-heading-three-with-arrow"
                        >
                            <button
                                onClick={() => {
                                    setExpandedIndex(2)
                                }}
                                className="accordion-toggle group inline-flex items-center justify-between leading-8 text-gray-900 w-full transition duration-500 text-left hover:text-indigo-600 "
                                aria-controls="basic-collapse-three-with-arrow"
                            >
                                <h5>Can I rent a vehicle for someone else?</h5>
                                <svg
                                    className={`text-gray-500 transition duration-500 group-hover:text-indigo-600   ${expandedIndex === 2 ? "rotate-180" : ""}`}
                                    width="22"
                                    height="22"
                                    viewBox="0 0 22 22"
                                    fill="none"
                                    xmlns="http://www.w3.org/2000/svg"
                                >
                                    <path
                                        d="M16.5 8.25L12.4142 12.3358C11.7475 13.0025 11.4142 13.3358 11 13.3358C10.5858 13.3358 10.2525 13.0025 9.58579 12.3358L5.5 8.25"
                                        stroke="currentColor"
                                        stroke-width="1.6"
                                        stroke-linecap="round"
                                        stroke-linejoin="round"
                                    ></path>
                                </svg>
                            </button>
                            <div
                                id="basic-collapse-three-with-arrow"
                                className={`w-full px-0 overflow-hidden ${expandedIndex === 2 ? "" : "h-0"} ease-in`}
                                aria-labelledby="basic-heading-three-with-arrow"
                            >
                                <p className="text-base text-gray-900 leading-6">
                                You can book a vehicle on behalf of someone else, but the person driving must meet all rental requirements, including presenting their own valid driver's license at the time of pickup.
                                </p>
                            </div>
                        </div>
                        <div
                            className="accordion py-8 px-6 transition-all duration-500 rounded-2xl hover:bg-indigo-50 accordion-active:bg-indigo-50"
                            id="basic-heading-three-with-arrow"
                        >
                            <button
                                onClick={() => {
                                    setExpandedIndex(3)
                                }}
                                className="accordion-toggle group inline-flex items-center justify-between leading-8 text-gray-900 w-full transition duration-500 text-left hover:text-indigo-600 "
                                aria-controls="basic-collapse-three-with-arrow"
                            >
                                <h5>How do I find my purchase history?</h5>
                                <svg
                                    className={`text-gray-500 transition duration-500 group-hover:text-indigo-600   ${expandedIndex === 3 ? "rotate-180" : ""}`}
                                    width="22"
                                    height="22"
                                    viewBox="0 0 22 22"
                                    fill="none"
                                    xmlns="http://www.w3.org/2000/svg"
                                >
                                    <path
                                        d="M16.5 8.25L12.4142 12.3358C11.7475 13.0025 11.4142 13.3358 11 13.3358C10.5858 13.3358 10.2525 13.0025 9.58579 12.3358L5.5 8.25"
                                        stroke="currentColor"
                                        stroke-width="1.6"
                                        stroke-linecap="round"
                                        stroke-linejoin="round"
                                    ></path>
                                </svg>
                            </button>
                            <div
                                id="basic-collapse-three-with-arrow"
                                className={`w-full px-0 overflow-hidden ${expandedIndex === 3 ? "" : "h-0"} ease-in`}
                                aria-labelledby="basic-heading-three-with-arrow"
                            >
                                <p className="text-base text-gray-900 leading-6">
                                    To contact customer support, look for a 'Contact us' or 'Help'
                                    button or link on the website or platform. You may be able to
                                    email, call, or chat with customer support for assistance.
                                </p>
                            </div>
                        </div>
                    </div>
                </div>
            </section>

        </>
    )
}

export default Contact