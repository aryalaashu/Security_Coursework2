import { Field, Form, Formik } from 'formik';
import React from 'react'
import Modal from 'react-modal'
import FieldError from '../../components/FieldError';
import axios from '../../axios';
import toast from 'react-hot-toast';
import dayjs from 'dayjs';

function EditBookingModal({ modalIsOpen, closeModal, getRoute, data, isOwner = false }) {

    const handleFormSubmit = async (values, actions) => {
        try {
            let result = await axios.put('/booking/' + data._id, {
                contact: values.contact,
                address: values.address,
                drop_date: values.drop_date,
                pickup_date: values.pickup_date,
            })

            if (result.data.success) {
                toast.success('Details Edited Successfully')
                closeModal()
                getRoute()
            } else toast.error('Failed')
        } catch (ERR) {
            console.log(ERR)
            toast.error(ERR.response.data.msg)
        }
    }

    return (
        <Modal
            ariaHideApp={false}
            isOpen={modalIsOpen}
            onRequestClose={closeModal}
            contentLabel="Edit Booking Modal"
            overlayClassName="Overlay"
            className="Modal rounded-md p-5 md:w-2/4 max-h-screen overflow-auto"
        >
            <h1 className="text-4xl font-bold tracking-tight text-gray-900">Edit Booking Details</h1>

            <div className='mt-4'>
                <Formik
                    enableReinitialize
                    initialValues={{
                        firstname: data.user.firstname,
                        lastname: data.user.lastname,
                        contact: data.contact,
                        address: data.address,
                        drop_date: dayjs(data.drop_date).format('YYYY-MM-DD'),
                        pickup_date: dayjs(data.pickup_date).format('YYYY-MM-DD'),
                    }}
                    onSubmit={(values, actions) => {
                        handleFormSubmit(values, actions);
                    }}
                >
                    {(props) => (
                        <Form className='gap-3 grid md:grid-cols-2'>
                            <div className=''>
                                <label htmlFor="firstname" className="block text-sm font-medium leading-6 text-gray-900">
                                    First Name
                                </label>
                                <div className="mt-2">
                                    <Field
                                        disabled
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
                                        disabled
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

                            {
                                isOwner &&
                                <>
                                    <div className='w-full'>
                                        <label>Pickup Date</label>
                                        <Field className='inputfield mt-2' required name='pickup_date' type='date' />
                                        <FieldError message={props.touched.pickup_date && props.errors.pickup_date} />
                                    </div>
                                    <div className='w-full'>
                                        <label>Drop Date</label>
                                        <Field className='inputfield mt-2' required name='drop_date' type='date' min={props.values.pickup_date} />
                                        <FieldError message={props.touched.drop_date && props.errors.drop_date} />
                                    </div>
                                </>
                            }



                            <div className='col-span-full mt-4'>
                                <button
                                    type="submit"
                                    className="flex w-full justify-center rounded-md bg-indigo-600 px-3 py-1.5  text-sm font-semibold leading-6 text-white shadow-sm hover:bg-indigo-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-600"
                                >
                                    Register
                                </button>
                            </div>


                        </Form>
                    )}
                </Formik>
            </div>

        </Modal>
    )
}

export default EditBookingModal