import { Field, Form, Formik } from 'formik';
import axios from '../../axios'
import React, { useContext } from 'react'
import toast from 'react-hot-toast'
import Modal from 'react-modal'
import FieldError from '../../components/FieldError';
import * as yup from 'yup';
import { AuthContext } from '../../context/authContext'

function EditProfile({ modalIsOpen, closeModal, getRoute, profileDetails }) {


    const { userDetails } = useContext(AuthContext)


    const validationSchema = yup.object({
        firstname: yup.string()
            .required('This Field is required'),
        lastname: yup.string()
            .required('This Field is required'),
        email: yup.string()
            .required('This Field is required'),
        contact: yup.string()
            .required("Phone number is required")
            .matches(/^[9]\d{9}$/, "Invalid phone number"),
        address: yup.string()
            .required('This Field is required'),
    });

    const handleFormSubmit = async (values, actions) => {
        try {
            // Make an Axios POST request
            const response = await axios.put('/user/update-profile/' + userDetails._id, values);

            if (response.data.success) {
                toast.success('Editing Successfull')
                getRoute()
                closeModal()
            }

            // Handle the response as needed (e.g., redirect, show a success message)
        } catch (error) {
            // Handle errors (e.g., show an error message)
            console.error('Error submitting form:', error);
            toast.error(error.response.data.msg)
        }
    };


    return (
        // <Modal
        //     ariaHideApp={false}
        //     isOpen={modalIsOpen}
        //     onRequestClose={closeModal}
        //     contentLabel="Add Category Modal"
        //     overlayClassName="Overlay"
        //     className="Modal rounded-md p-5 md:w-1/4 max-h-screen overflow-auto"
        // >
        <div className='bg-white px-10 p-4 rounded-lg'>
            <div className="sm:mx-auto sm:w-full sm:max-w-sm">
                <h2 className="mt-5 text-center text-2xl font-bold leading-9 tracking-tight text-gray-900">
                    Profile Details
                </h2>
            </div>

            <div className="mt-10 ">

                <Formik
                    enableReinitialize
                    initialValues={{
                        firstname: profileDetails?.firstname,
                        lastname: profileDetails?.lastname,
                        email: profileDetails?.email,
                        contact: profileDetails?.contact,
                        address: profileDetails?.address,
                    }}
                    validationSchema={validationSchema}
                    onSubmit={(values, actions) => {
                        handleFormSubmit(values, actions);
                    }}
                >
                    {(props) => (
                        <Form className='gap-3 grid grid-cols-2'>
                            <div className=''>
                                <label htmlFor="firstname" className="block text-sm font-medium leading-6 text-gray-900">
                                    First Name
                                </label>
                                <div className="mt-2">
                                    <Field
                                        id="firstname"
                                        name="firstname"
                                        autoComplete="firstname"
                                        required
                                        className="block w-full rounded-md border-0 py-1.5 px-2 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"
                                    />
                                </div>
                                <FieldError message={props.touched.firstname && props.errors.firstname} />

                            </div>
                            <div>
                                <label htmlFor="lastname" className="block text-sm font-medium leading-6 text-gray-900">
                                    Last Name
                                </label>
                                <div className="mt-2">
                                    <Field
                                        id="lastname"
                                        name="lastname"
                                        autoComplete="lastname"
                                        required
                                        className="block w-full rounded-md border-0 py-1.5 px-2 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"
                                    />
                                </div>
                                <FieldError message={props.touched.lastname && props.errors.lastname} />

                            </div>

                            <div className=''>
                                <label htmlFor="address" className="block  text-sm font-medium leading-6 text-gray-900">
                                    Address
                                </label>
                                <div className="mt-2">
                                    <Field
                                        id="address"
                                        name="address"
                                        autoComplete="address"
                                        required
                                        className="block w-full rounded-md border-0 py-1.5 px-2 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"
                                    />
                                </div>
                                <FieldError message={props.touched.address && props.errors.address} />

                            </div>
                            <div>
                                <label htmlFor="contact" className="block text-sm font-medium leading-6 text-gray-900">
                                    Contact
                                </label>
                                <div className="mt-2">
                                    <Field
                                        id="contact"
                                        name="contact"
                                        autoComplete="contact"
                                        required
                                        className="block w-full rounded-md border-0 py-1.5 px-2 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"
                                    />
                                </div>
                                <FieldError message={props.touched.contact && props.errors.contact} />

                            </div>


                            <div className='col-span-full text-center opacity-15'>
                                ------------
                            </div>

                            <div className='col-span-full -mt-3'>
                                <label htmlFor="email" className="block text-sm font-medium leading-6 text-gray-900">
                                    Email address
                                </label>
                                <div className="mt-2">
                                    <Field
                                        id="email"
                                        name="email"
                                        type="email"
                                        autoComplete="email"
                                        required
                                        className="block w-full rounded-md border-0 py-1.5 px-2 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"
                                    />
                                </div>
                                <FieldError message={props.touched.email && props.errors.email} />

                            </div>

                            <div className='col-span-full mt-4 flex gap-3'>
                                <button
                                    type="submit"
                                    className="flex w-full justify-center rounded-md bg-indigo-600 px-3 py-1.5  text-sm font-semibold leading-6 text-white shadow-sm hover:bg-indigo-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-600"
                                >
                                    Submit
                                </button>
                                {/* <button
                                    onClick={() => {
                                        closeModal()
                                    }}
                                    type="button"
                                    className="flex w-full justify-center rounded-md bg-gray-600 px-3 py-1.5 text-sm font-semibold leading-6 text-white shadow-sm hover:bg-gray-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-600"
                                >
                                    Close
                                </button> */}
                            </div>


                        </Form>
                    )}
                </Formik>

            </div>
        </div>

        // </Modal>
    )
}

export default EditProfile