import axios from "axios";
import toast from "react-hot-toast";

// console.log("token", localStorage.getItem("_hw_token"));

const accessToken = localStorage.getItem("_hw_token");

const instance = axios.create({
  baseURL: process.env.REACT_APP_BASE_URI,
  withCredentials: true,
  headers: {
    Authorization: accessToken,
  },
});

instance.interceptors.request.use(function (config) {
  const token = localStorage.getItem("_hw_token");
  config.headers.Authorization = token ? `Bearer ${token}` : "";
  return config;
});

instance.interceptors.response.use(function (response) {
  // Any status code that lie within the range of 2xx cause this function to trigger
  // Do something with response data
  return response;
}, function (error) {
  console.log('forma xios', error.response.status)
  if (error.response.status === 422) {
    toast.error('TOken Expired, Login Again..')
    localStorage.removeItem("_hw_token");
    localStorage.removeItem("_hw_userDetails");

    setTimeout(() => {
        window.location.href = "/login"
    }, 400)
  }
  // Any status codes that falls outside the range of 2xx cause this function to trigger
  // Do something with response error
  return Promise.reject(error);
});

export default instance;
