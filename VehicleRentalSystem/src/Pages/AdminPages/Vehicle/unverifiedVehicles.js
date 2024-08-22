import React from 'react'
import { FaCheck } from 'react-icons/fa';

function UnverifiedVehicles({ vehicleData, totalVehicleCount, vehiclePageSize, setCurrentVehiclePage, setVehiclePageSize, currentVehiclePage, totalVehiclePage, verifyvehicle }) {
    return (
        <div className="w-full my-5  bg-white">
            <table className="table-auto rounded-lg border w-full text-left ">
                <thead className="font-semibold border-b bg-blue-100">
                    <tr className="opacity-75">
                        <th className="p-3">S.N</th>
                        <th className="p-3">Vehicle Name</th>
                        <th className="p-3">Rate per day</th>
                        <th className="p-3">Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {vehicleData &&
                        (vehicleData.length === 0 ? (
                            <p className="p-5 font-semibold text-red-800">No Data</p>
                        ) : (
                            vehicleData.map((value, index) => (
                                <tr key={index} className="border-b">
                                    <td className="p-3">{index + 1}</td>
                                    <td className="p-3">{value?.name}</td>
                                    <td className="p-3">Rs. {value?.price}</td>
                                    <td className="p-3 flex gap-2 flex-wrap max-w-fit">
                                        <button
                                            onClick={() => {
                                                // setSelectedVehicleData(value);
                                                verifyvehicle(value?._id);
                                            }}
                                            className="bg-blue-700 text-white p-2 rounded"
                                        >
                                            <FaCheck />
                                        </button>

                                    </td>
                                </tr>
                            ))
                        ))}
                </tbody>
            </table>
            <div className="flex items-center justify-between border-t border-gray-200 bg-white px-4 py-3 sm:px-6">
                <div className="flex flex-1 justify-between sm:hidden">
                    <button className="relative inline-flex items-center rounded-md border border-gray-300 bg-white px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50">
                        Previous
                    </button>
                    <button className="relative ml-3 inline-flex items-center rounded-md border border-gray-300 bg-white px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50">
                        Next
                    </button>
                </div>
                <div className="hidden sm:flex sm:flex-1 sm:items-center sm:justify-between">
                    <div className="text-sm text-gray-700">
                        <p className="font-semibold">{totalVehicleCount} Total Results</p>
                    </div>
                    <div className="flex flex-wrap items-center gap-3">
                        <label>Showing</label>
                        <select
                            defaultValue={vehiclePageSize}
                            className="border rounded py-1"
                            onChange={(e) => {
                                setCurrentVehiclePage(1);
                                setVehiclePageSize(e.target.value);
                            }}
                        >
                            <option>1</option>
                            <option>5</option>
                            <option>10</option>
                            <option>20</option>
                        </select>
                        <nav
                            className="isolate inline-flex -space-x-px rounded-md shadow-sm"
                            aria-label="Pagination"
                        >
                            <button
                                disabled={currentVehiclePage === 1}
                                onClick={() => {
                                    setCurrentVehiclePage(currentVehiclePage - 1);
                                }}
                                className="relative inline-flex items-center rounded-l-md px-2 py-2 text-gray-400 ring-1 ring-inset ring-gray-300 hover:bg-gray-50 focus:z-20 focus:outline-offset-0"
                            >
                                <span className="sr-only">Previous</span>
                                <svg
                                    className="h-5 w-5"
                                    viewBox="0 0 20 20"
                                    fill="currentColor"
                                    aria-hidden="true"
                                >
                                    <path
                                        fillRule="evenodd"
                                        d="M12.79 5.23a.75.75 0 01-.02 1.06L8.832 10l3.938 3.71a.75.75 0 11-1.04 1.08l-4.5-4.25a.75.75 0 010-1.08l4.5-4.25a.75.75 0 011.06.02z"
                                        clipRule="evenodd"
                                    />
                                </svg>
                            </button>

                            <span className="relative inline-flex items-center px-4 py-2 text-sm font-semibold text-gray-900 ring-1 ring-inset ring-gray-300 hover:bg-gray-50 focus:z-20 focus:outline-offset-0">
                                Page {currentVehiclePage} of {totalVehiclePage}
                            </span>

                            <button
                                disabled={currentVehiclePage === totalVehiclePage}
                                onClick={() => {
                                    setCurrentVehiclePage(currentVehiclePage + 1);
                                }}
                                className="relative inline-flex items-center rounded-r-md px-2 py-2 text-gray-400 ring-1 ring-inset ring-gray-300 hover:bg-gray-50 focus:z-20 focus:outline-offset-0"
                            >
                                <span className="sr-only">Next</span>
                                <svg
                                    className="h-5 w-5"
                                    viewBox="0 0 20 20"
                                    fill="currentColor"
                                    aria-hidden="true"
                                >
                                    <path
                                        fillRule="evenodd"
                                        d="M7.21 14.77a.75.75 0 01.02-1.06L11.168 10 7.23 6.29a.75.75 0 111.04-1.08l4.5 4.25a.75.75 0 010 1.08l-4.5 4.25a.75.75 0 01-1.06-.02z"
                                        clipRule="evenodd"
                                    />
                                </svg>
                            </button>
                        </nav>
                    </div>
                </div>
            </div>
        </div>
    )
}

export default UnverifiedVehicles