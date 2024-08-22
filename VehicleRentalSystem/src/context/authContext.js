import React, { createContext, useEffect, useState } from "react";

export const AuthContext = createContext();

const AuthContextProvider = ({ children }) => {

  const [authUser, setAuthUser] = useState();
  const [profileDetail, setProfileDetail] = useState();
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [userDetails, setUserDetails] = useState(() => localStorage.getItem('_hw_userDetails') ? JSON.parse(localStorage.getItem('_hw_userDetails')) : "");

  const token = localStorage.getItem('_hw_token')

  useEffect(() => {
    setUserDetails(JSON.parse(localStorage.getItem('_hw_userDetails')))
    if (token) {
      setIsAuthenticated(true)
    } else setIsAuthenticated(false)
  }, [token])

 
  return (
    <AuthContext.Provider
      value={{
        isAuthenticated,
        setIsAuthenticated,
        authUser,
        setAuthUser,
        userDetails,
        setUserDetails,
        profileDetail,
        setProfileDetail
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export default AuthContextProvider;
