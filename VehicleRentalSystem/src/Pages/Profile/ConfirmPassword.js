import { Field, Form, Formik } from 'formik';
import axios from '../../axios'
import React, { useContext } from 'react'
import toast from 'react-hot-toast'
import Modal from 'react-modal'
import FieldError from '../../components/FieldError';
import * as yup from 'yup';
import { AuthContext } from '../../context/authContext'

function ConfirmPassword({ modalIsOpen, closeModal, getRoute, profileDetails }) {

    const { userDetails } = useContext(AuthContext)

    const validationSchema = yup.object({
        currentPassword: yup.string()
            .required('This Field is required'),
        password: yup.string().required('Password is required'),
        confirmPassword: yup.string()
            .oneOf([yup.ref('password'), null], 'Passwords must match')
    });

    const handleFormSubmit = async (values, actions) => {
        try {
            // Make an Axios POST request
            const response = await axios.put('/user/change-password/', {
                password: values.password,
                oldpassword: values.currentPassword
            });

            if (response.data.success) {
                toast.success('Password Changed')
                actions.resetForm()
            }

            // Handle the response as needed (e.g., redirect, show a success message)
        } catch (error) {
            // Handle errors (e.g., show an error message)
            console.error('Error submitting form:', error);
            toast.error(error.response.data.msg)
        }
    };


    return (
        <div className='bg-white px-10 p-4 rounded-lg'>
            <div className="sm:mx-auto sm:w-full sm:max-w-sm">
                <h2 className="mt-5 text-center text-2xl font-bold leading-9 tracking-tight text-gray-900">
                    Change Password
                </h2>
            </div>

            <div className="mt-10 ">

                <Formik
                    enableReinitialize
                    initialValues={{
                        currentPassword: "",
                        password: "",
                        confirmPassword: "",
                    }}
                    validationSchema={validationSchema}
                    onSubmit={(values, actions) => {
                        handleFormSubmit(values, actions);
                    }}
                >
                    {(props) => (
                        <Form className='gap-3 grid max-w-xl mx-auto'>
                            <div className=''>
                                <label htmlFor="currentPassword" className="block text-sm font-medium leading-6 text-gray-900">
                                    Current Password
                                </label>
                                <div className="mt-2">
                                    <Field
                                        type="password"
                                        id="currentPassword"
                                        name="currentPassword"
                                        autoComplete="currentPassword"
                                        required
                                        className="block w-full rounded-md border-0 py-1.5 px-2 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"
                                    />
                                </div>
                                <FieldError message={props.touched.currentPassword && props.errors.currentPassword} />

                            </div>
                            <div className=''>
                                <label htmlFor="password" className="block text-sm font-medium leading-6 text-gray-900">
                                    New Password
                                </label>
                                <div className="mt-2">
                                    <Field
                                        type="password"
                                        id="password"
                                        name="password"
                                        autoComplete="password"
                                        required
                                        className="block w-full rounded-md border-0 py-1.5 px-2 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"
                                    />
                                </div>
                                <FieldError message={props.touched.password && props.errors.password} />

                            </div>
                            <div>
                                <label htmlFor="confirmPassword" className="block text-sm font-medium leading-6 text-gray-900">
                                    Confirm Password
                                </label>
                                <div className="mt-2">
                                    <Field
                                        type="password"
                                        id="confirmPassword"
                                        name="confirmPassword"
                                        autoComplete="confirmPassword"
                                        required
                                        className="block w-full rounded-md border-0 py-1.5 px-2 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"
                                    />
                                </div>
                                <FieldError message={props.touched.confirmPassword && props.errors.confirmPassword} />
                            </div>

                            <div className='col-span-full mt-4 flex gap-3'>
                                <button
                                    type="submit"
                                    className="flex w-full justify-center rounded-md bg-indigo-600 px-3 py-1.5  text-sm font-semibold leading-6 text-white shadow-sm hover:bg-indigo-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-600"
                                >
                                    Submit
                                </button>
                            </div>


                        </Form>
                    )}
                </Formik>

            </div>
        </div>
    )
}

export default ConfirmPassword