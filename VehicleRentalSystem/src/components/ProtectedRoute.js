import React from "react";
import { Navigate } from "react-router-dom";

const ProtectedRoute = ({ children }) => {

  const userDetails = JSON.parse(localStorage?.getItem("_hw_userDetails"));

  const userRole = userDetails?.role;

  if (userRole) {
    return children;
  }

  return <Navigate to="/" replace />;
};

export default ProtectedRoute;
