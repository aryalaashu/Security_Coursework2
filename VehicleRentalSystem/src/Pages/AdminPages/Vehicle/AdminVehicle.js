import React, { useEffect, useState } from "react";
import axios from "../../../axios";
import toast from "react-hot-toast";
import Swal from "sweetalert2";
import { FaCheck, FaEdit, FaEye, FaTrashAlt, FaUser } from "react-icons/fa";
import AddVehicle from "./AddVehicle";
import EditVehicle from "./EditVehicle";
import VehicleLog from "./VehicleLog";
import UnverifiedVehicles from "./unverifiedVehicles";
import { Link } from "react-router-dom";

function AdminVehicle() {
    const [isAddModalOpen, setIsAddModalOpen] = useState(false);
    const [isEditModalOpen, setIsEditModalOpen] = useState(false);
    const [isAttendanceModalOpen, setIsAttendanceModalOpen] = useState(false);

    const [vehicleData, setVehicleData] = useState([]);
    const [selectedVehicleData, setSelectedVehicleData] = useState([]);
    const [totalVehicleCount, setTotalVehicleCount] = useState(0);
    const [totalVehiclePage, setTotalVehiclePage] = useState(1);
    const [currentVehiclePage, setCurrentVehiclePage] = useState(1);

    const [showVerified, setShowVerified] = useState(true);

    const [unverifiedTotalVehicleCount, setUnverifiedTotalVehicleCount] = useState(0);
    const [unverifiedVehicleData, setUnverifiedVehicleData] = useState([]);
    const [unverifiedCurrentVehiclePage, setCurrentUnverifiedVehiclePage] = useState(1);
    const [totalUnverifiedVehiclePage, setTotalUnverifiedVehiclePage] = useState(1);

    const [vehiclePageSize, setVehiclePageSize] = useState(10);
    const [keyword, setKeyword] = useState("");

    const removeItem = async (id) => {
        try {
            Swal.fire({
                title: "Are you sure?",
                text: "You won't be able to revert this!",
                icon: "warning",
                showCancelButton: true,
                confirmButtonColor: "#3085d6",
                cancelButtonColor: "#d33",
                confirmButtonText: "Yes, Delete it!",
            }).then(async (result) => {
                if (result.isConfirmed) {
                    let result = await axios.delete("vehicle/" + id);
                    if (result.data.success) {
                        getAllVehicle();
                        toast.success("Deleted Successfully");
                    }
                }
            });
        } catch (ERR) {
            console.log(ERR);
            toast.error(ERR.response.data.msg);
        }
    };

    const verifyvehicle = async (id) => {
        try {
            Swal.fire({
                title: "Are you sure?",
                text: "You won't be able to revert this!",
                icon: "warning",
                showCancelButton: true,
                confirmButtonColor: "#3085d6",
                cancelButtonColor: "#d33",
                confirmButtonText: "Yes, Verify it!",
            }).then(async (result) => {
                if (result.isConfirmed) {
                    let result = await axios.put("vehicle/verify-vehicle/" + id);
                    if (result.data.success) {
                        getAllVehicle();
                        getAllUnverifiedVehicle()
                        toast.success("Verified Successfully");
                    }
                }
            });
        } catch (ERR) {
            console.log(ERR);
            toast.error(ERR.response.data.msg);
        }
    };

    const closeAddModal = () => {
        setIsAddModalOpen(false);
    };
    const openAddModal = () => {
        setIsAddModalOpen(true);
    };

    const closeEditModal = () => {
        setIsEditModalOpen(false);
    };
    const openEditModal = () => {
        setIsEditModalOpen(true);
    };
    const closeAttendanceModal = () => {
        setIsAttendanceModalOpen(false);
    };
    const openAttendanceModal = () => {
        setIsAttendanceModalOpen(true);
    };

    const getAllVehicle = async () => {
        try {
            let result = await axios.get("/vehicle", {
                params: {
                    search: keyword,
                    page: currentVehiclePage,
                    size: vehiclePageSize,
                },
            });

            if (result.data.success) {
                setVehicleData(result.data.data);
                setTotalVehicleCount(result.data.totalCount);
                setTotalVehiclePage(Math.ceil(result.data.totalCount / result.data.size));
            } else toast.error("Failed");
        } catch (ERR) {
            console.log(ERR);
            toast.error(ERR.response.data.msg);
        }
    };

    const getAllUnverifiedVehicle = async () => {
        try {
            let result = await axios.get("/vehicle/unverified-vehicle", {
                params: {
                    search: keyword,
                    page: currentVehiclePage,
                    size: vehiclePageSize,
                },
            });

            if (result.data.success) {
                setUnverifiedVehicleData(result.data.data);
                setUnverifiedTotalVehicleCount(result.data.totalCount);
                setTotalUnverifiedVehiclePage(Math.ceil(result.data.totalCount / result.data.size));
            } else toast.error("Failed");
        } catch (ERR) {
            console.log(ERR);
            toast.error(ERR.response.data.msg);
        }
    };

    useEffect(() => {
        getAllVehicle();
    }, [keyword, currentVehiclePage, vehiclePageSize]);

    useEffect(() => {
        getAllUnverifiedVehicle()
    }, [keyword, currentVehiclePage, vehiclePageSize]);


    const getBothData = () => {
        getAllVehicle()
        getAllUnverifiedVehicle()
    }

    return (
        <div className="mx-auto max-w-7xl px-4">
            {isAddModalOpen && (
                <AddVehicle
                    closeModal={closeAddModal}
                    modalIsOpen={isAddModalOpen}
                    getRoute={getBothData}
                />
            )}
            {isEditModalOpen && (
                <EditVehicle
                    closeModal={closeEditModal}
                    modalIsOpen={isEditModalOpen}
                    getRoute={getBothData}
                    data={selectedVehicleData}
                />
            )}
            {isAttendanceModalOpen && (
                <VehicleLog
                    closeModal={closeAttendanceModal}
                    modalIsOpen={isAttendanceModalOpen}
                    getRoute={getBothData}
                    data={selectedVehicleData}
                />
            )}


            <div className="flex items-baseline justify-between  pb-6 pt-5">
                <h1 className="text-4xl font-bold tracking-tight text-gray-900">
                    Vehicle
                </h1>
                <button
                    onClick={() => {
                        openAddModal();
                    }}
                    className="bg-blue-800 p-3 rounded-md text-white font-semibold px-4"
                >
                    Add Vehicle
                </button>
            </div>
            <div>
                <input
                    className="border p-2"
                    type="string"
                    placeholder="Search"
                    onChange={(e) => {
                        setKeyword(e.target.value);
                        setCurrentVehiclePage(1);
                    }}
                />
            </div>


            <div className="my-3 flex flex-wrap gap-3">
                <button onClick={() => {
                    setShowVerified(true)
                }} className={`${showVerified ? "btn-primary" : "btn-outline"}`}>Verified</button>
                <button onClick={() => {
                    setShowVerified(false)
                }} className={`${!showVerified ? "btn-primary" : "btn-outline"}`}>Un-Verified ( {unverifiedTotalVehicleCount} )</button>
            </div>


            {
                showVerified ?
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
                                                    <Link to={'/vehicle/' + value.sku} className="bg-blue-700 text-white p-2 rounded" >
                                                        <FaEye />
                                                    </Link>
                                                    {/* <button
                                                onClick={() => {
                                                    setSelectedVehicleData(value);
                                                    openAttendanceModal();
                                                }}
                                                className="bg-blue-700 text-white p-2 rounded"
                                            >
                                                <FaUser />
                                            </button> */}
                                                    {/* <button
                                                className="bg-red-700 text-white p-2 rounded"
                                                onClick={() => {
                                                    removeItem(value._id);
                                                }}
                                            >
                                                <FaTrashAlt />
                                            </button> */}
                                                    {/* <button
                                                onClick={() => {
                                                    setSelectedVehicleData(value);
                                                    openEditModal();
                                                }}
                                                className="bg-blue-700 text-white p-2 rounded"
                                            >
                                                <FaEdit />
                                            </button> */}
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
                    :
                    <UnverifiedVehicles
                        vehicleData={unverifiedVehicleData}
                        currentVehiclePage={unverifiedCurrentVehiclePage}
                        setCurrentVehiclePage={setCurrentUnverifiedVehiclePage}
                        setVehiclePageSize={setVehiclePageSize}
                        totalVehicleCount={unverifiedTotalVehicleCount}
                        totalVehiclePage={totalUnverifiedVehiclePage}
                        vehiclePageSize={vehiclePageSize}
                        verifyvehicle={verifyvehicle}
                    />
            }
        </div>
    );
}

export default AdminVehicle;
