import React from "react";
import { Link } from "react-router-dom";

function SideNav({ setSideNav, sideNav }) {
  return (
    <div>
      <div
        className={`${!sideNav && "hidden"}  
        z-50 w-full h-screen flex top-0 overflow-y-auto overflow-x-hidden fixed sticky-0" id="chec-div`}
      >
        <div className="w-full absolute z-50 right-0 h-full overflow-x-hidden transform translate-x-0 transition ease-in-out duration-700">
          <div className="w-80 z-10 bg-white h-screen overflow-y-auto absolute left-0 ">
            <div className="flex items-center justify-between py-3 px-4">
              <Link to="/">
                <img src="/logowithLabel.png" className="h-20 -mb-4" alt="logo" />
              </Link>
              <button
                onClick={() => setSideNav(false)}
                aria-label="close modal"
                className="focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-500 rounded-md cursor-pointer"
              >
                <img
                  src="https://tuk-cdn.s3.amazonaws.com/can-uploader/notification_1-svg1.svg"
                  alt="icon"
                />
              </button>
            </div>

            {/* NOTIFICATION FEED */}
            <div className="mt-5">
              <Link className="cursor-pointer" to={"/"}>
                <div className="w-full py-3 px-4 bg-white rounded flex items-center">
                  <div className="pl-3">
                    <label className="font-semibold cursor-pointer">Home</label>
                  </div>
                </div>
              </Link>

              <Link className="cursor-pointer" to={"/"}>
                <div className="w-full py-3 px-4 bg-white rounded flex items-center">
                  <div className="pl-3">
                    <label className="font-semibold cursor-pointer">
                      Categories
                    </label>
                  </div>
                </div>
              </Link>

              {/* <Link className="cursor-pointer" to={"/"}>
                <div className="w-full py-3 px-4 bg-white rounded flex items-center">
                  <div className="pl-3">
                    <label className="font-semibold cursor-pointer">
                      About
                    </label>
                  </div>
                </div>
              </Link> */}
            </div>
          </div>

          <div
            onClick={() => setSideNav(!sideNav)}
            className=" bg-gray-100 bg-opacity-60 top-0 right-0 overflow-y-auto overflow-x-hidden fixed sticky-0 w-full h-screen"
          />
        </div>
      </div>
    </div>
  );
}

export default SideNav;
