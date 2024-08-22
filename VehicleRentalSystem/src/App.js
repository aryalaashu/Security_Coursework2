import { Route, Routes } from 'react-router-dom';
import './App.css';
import Home from './Pages/Home/Home';
import Login from './Pages/Login/Login';
import Page404 from './Pages/404/Page404';
import AppNavbar from './components/AppNavbar';
import Signup from './Pages/Signup/Signup';
import Contact from './Pages/Contact/Contact';
import { Toaster } from 'react-hot-toast';
import AuthContextProvider from './context/authContext';
import ProtectedRoute from './components/ProtectedRoute';
import Dashboard from './Pages/AdminPages/Dashboard';
import AdminNavbar from './components/AdminComponents/AdminNavbar';
import ProtectedAdminRoute from './components/AdminComponents/ProtectedAdminRoute';
import User from './Pages/AdminPages/User/User';
import Profile from './Pages/Profile/Profile';
import Footer from './components/Footer';
import AdminContact from './Pages/AdminPages/Contact/AdminContact';
import Coaching from './Pages/Explore/Explore';
import Success from './Pages/payment/Success';
import Failed from './Pages/payment/Failed';
import About from './Pages/About/About';
import SingleVehicle from './Pages/Vehicle/SingleVehicle';
import AdminVehicle from './Pages/AdminPages/Vehicle/AdminVehicle';
import MyRentals from './Pages/MyRentals/MyRentals';
import BecomeAHost from './Pages/BecomeAHost/BecomeAHost';
import Services from './Pages/Services/Services';

function App() {

  return (
    <div>
      <AuthContextProvider>
        <Toaster position='top-right' />
        <div className='min-h-screen flex flex-col'>
          <AppNavbar />
          <AdminNavbar />
          <div className='flex-1'>
            <Routes>
              <Route index element={<Home />} />
              <Route path="/" element={<Home />} />
              <Route path="/login" element={<Login />} />
              <Route path="/signup" element={<Signup />} />
              <Route path="/contact" element={<Contact />} />
              <Route path="/services" element={<Services />} />
              <Route path="/vehicle/:sku" element={<SingleVehicle />} />

              <Route path="/explore" element={<Coaching />} />
              <Route path="/success" element={<Success />} />
              <Route path="/failure" element={<Failed />} />
              <Route path="/about" element={<About />} />

              {/* Auth Pages */}

              <Route
                path="/profile"
                element={
                  <ProtectedRoute>
                    <Profile />
                  </ProtectedRoute>
                }
              />
              <Route
                path="/my-rentals"
                element={
                  <ProtectedRoute>
                    <MyRentals />
                  </ProtectedRoute>
                }
              />
              <Route
                path="/become-a-host"
                element={
                  <ProtectedRoute>
                    <BecomeAHost />
                  </ProtectedRoute>
                }
              />

              {/* 404 Page */}
              <Route path="*" element={<Page404 />} />

              {/* Admin Pages */}
              <Route
                path="/dashboard"
                element={
                  <ProtectedAdminRoute>
                    <Dashboard />
                  </ProtectedAdminRoute>
                }
              />
              <Route
                path="/dashboard/vehicle"
                element={
                  <ProtectedAdminRoute>
                    <AdminVehicle />
                  </ProtectedAdminRoute>
                }
              />
              <Route
                path="/dashboard/users"
                element={
                  <ProtectedAdminRoute>
                    <User />
                  </ProtectedAdminRoute>
                }
              />
              <Route
                path="/dashboard/contact"
                element={
                  <ProtectedAdminRoute>
                    <AdminContact />
                  </ProtectedAdminRoute>
                }
              />

            </Routes>
          </div>
          <Footer />
        </div>
      </AuthContextProvider>
    </div>
  );
}

export default App;
