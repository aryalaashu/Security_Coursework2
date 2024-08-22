import { useContext, useState } from 'react'
import { FaBars } from 'react-icons/fa'
import { MdClose } from 'react-icons/md'
import { Link, useLocation } from 'react-router-dom'
import { AuthContext } from '../../context/authContext'

const user = {
  name: 'Tom Cook',
  email: 'tom@example.com',
  imageUrl:
    'https://images.unsplash.com/photo-1472099645785-5658abf4ff4e?ixlib=rb-1.2.1&ixid=eyJhcHBfaWQiOjEyMDd9&auto=format&fit=facearea&facepad=2&w=256&h=256&q=80',
}
const navigation = [
  { name: 'dashboard', href: '/dashboard' },
  // { name: 'users', href: '/dashboard/users' },
  { name: 'vehicle', href: '/dashboard/vehicle' },
  // { name: 'events', href: '/dashboard/events' },
  { name: 'contact', href: '/dashboard/contact' },
  // { name: 'blog', href: '/dashboard/blog' },
  // { name: 'sessions', href: '/dashboard/sessions' },
]
const userNavigation = [
  { name: 'Your Profile', href: '/profile' },
]

export default function AdminNavbar() {

  const [open, setOpen] = useState(false)
  const location = useLocation()

  const authUser = useContext(AuthContext)

  if (!location.pathname.includes("/dashboard")) {
    return
  }

  const logout = () => {
    localStorage.removeItem("_hw_token");
    localStorage.removeItem("_hw_userDetails");

    setTimeout(() => {
      window.location.href = "/login"
    }, 400)
  };

  return (
    <div className={`min-h-full sticky top-0 mb-10`}>
      <div className="bg-gray-800">
        <>
          <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
            <div className="flex h-16 items-center justify-between">
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <a href='/'>

                    <img
                      className="h-8 w-12"
                      src="/app_logo.png"
                      alt="applog"
                    />
                  </a>
                </div>
                <div className="hidden md:block">
                  <div className="ml-10 flex items-baseline space-x-4">
                    {navigation.map((item) => (
                      <Link
                        key={item.name}
                        to={item.href}
                        className={(`${location.pathname === item.href
                          ? 'bg-gray-900 text-white'
                          : 'text-gray-300 hover:bg-gray-700 hover:text-white '
                          } rounded-md px-3 py-2 text-sm font-medium capitalize`)}
                        aria-current={item.current ? 'page' : undefined}
                      >
                        {item.name}
                      </Link>
                    ))}
                  </div>
                </div>
              </div>
              <div className="hidden md:block">
                <div className="ml-4 flex items-center md:ml-6">
                  {/* <button
                    type="button"
                    className="relative rounded-full bg-gray-800 p-1 text-gray-400 hover:text-white focus:outline-none focus:ring-2 focus:ring-white focus:ring-offset-2 focus:ring-offset-gray-800"
                  >
                    <span className="absolute -inset-1.5" />
                    <span className="sr-only">View notifications</span>
                    <FaBell className="h-6 w-6" aria-hidden="true" />
                  </button> */}

                  {/* Profile dropdown */}
                  <div className="relative ml-3 group">
                    {/* <button className="relative flex max-w-xs items-center rounded-full bg-gray-800 text-sm focus:outline-none focus:ring-2 focus:ring-white focus:ring-offset-2 focus:ring-offset-gray-800">
                      <span className="absolute -inset-1.5" />
                      <span className="sr-only">Open user menu</span>
                      <img className="h-8 w-8 rounded-full" src={user.imageUrl} alt="" />
                    </button> */}
                    {authUser?.userDetails?.image ? (
                      <img
                        className="w-7 rounded-full object-cover object-center sm:w-8 md:w-8 h-7"
                        src={`${process.env.REACT_APP_IMG_URI}${authUser?.userDetails?.image}`}
                        alt="user"
                      />
                    ) : (
                      <img
                        className="w-7 rounded-full object-cover object-center sm:w-8 md:w-7 h-7 border"
                        src="/defaultUserImage.png"
                        alt="user"
                      />)}
                    <div className='absolute bg-transparent shadow w-40 bg-white right-0 z-10 group-hover:block hidden min-w-max'>
                      {userNavigation.map((item) => (
                        <div key={item.name}>
                          <a
                            href={item.href}
                            className={
                              'hover:bg-gray-100 block px-4 py-2 text-sm hover:text-gray-700'
                            }
                          >
                            {item.name}
                          </a>
                        </div>
                      ))}
                      <div >
                        <button
                          onClick={() => {
                            localStorage.removeItem("_hw_token");
                            localStorage.removeItem("_hw_userDetails");

                            setTimeout(() => {
                              window.location.href = "/login"
                            }, 400)
                          }}
                          className={
                            'hover:bg-gray-100 w-full text-left block px-4 py-2 text-sm hover:text-gray-700'
                          }
                        >
                          Sign Out
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
              <div className="-mr-2 flex md:hidden">
                {/* Mobile menu button */}
                <button

                  onClick={() => {
                    setOpen(!open)
                  }}

                  className="relative inline-flex items-center justify-center rounded-md bg-gray-800 p-2 text-gray-400 hover:bg-gray-700 hover:text-white focus:outline-none focus:ring-2 focus:ring-white focus:ring-offset-2 focus:ring-offset-gray-800">
                  <span className="absolute -inset-0.5" />
                  <span className="sr-only">Open main menu</span>
                  {open ? (
                    <MdClose className="block h-6 w-6" aria-hidden="true" />
                  ) : (
                    <FaBars className="block h-6 w-6" aria-hidden="true" />
                  )}
                </button>
              </div>
            </div>
          </div>

          <div className={`md:hidden ${open ? "block" : "hidden"}`}>
            <div className="space-y-1 px-2 pb-3 pt-2 sm:px-3">
              {navigation.map((item) => (
                <Link
                  key={item.name}
                  to={item.href}
                  className={`${location.pathname === item.href
                    ? 'bg-gray-900 text-white'
                    : 'text-gray-300 hover:bg-gray-700 hover:text-white '
                    } block rounded-md px-3 py-2 text-base font-medium capitalize w-full text-left`}
                >
                  {item.name}
                </Link>
              ))}
            </div>
            <div className="border-t border-gray-700 pb-3 pt-4">
              <div className="flex items-center px-5">
                <div className="flex-shrink-0">
                  {authUser?.userDetails?.image ? (
                    <img
                      className="w-7 rounded-full object-cover object-center sm:w-8 md:w-8 h-7"
                      src={`${process.env.REACT_APP_IMG_URI}${authUser?.userDetails?.image}`}
                      alt="user"
                    />
                  ) : (
                    <img
                      className="w-7 rounded-full object-cover object-center sm:w-8 md:w-7 h-7 border"
                      src="/defaultUserImage.png"
                      alt="user"
                    />
                  )}
                </div>
                <div className="ml-3">
                  <div className="text-base font-medium leading-none text-white">{user.name}</div>
                  <div className="text-sm font-medium leading-none text-gray-400">{user.email}</div>
                </div>
                {/* <button
                  type="button"
                  className="relative ml-auto flex-shrink-0 rounded-full bg-gray-800 p-1 text-gray-400 hover:text-white focus:outline-none focus:ring-2 focus:ring-white focus:ring-offset-2 focus:ring-offset-gray-800"
                >
                  <span className="absolute -inset-1.5" />
                  <span className="sr-only">View notifications</span>
                  <FaBell className="h-6 w-6" aria-hidden="true" />
                </button> */}
              </div>
              <div className="mt-3 space-y-1 px-2">
                {userNavigation.map((item) => (
                  <button
                    key={item.name}
                    as="a"
                    href={item.href}
                    className="block rounded-md px-3 py-2 text-base font-medium text-gray-400 hover:bg-gray-700 hover:text-white"
                  >
                    {item.name}
                  </button>
                ))}
                <button
                  onClick={() => {
                    logout()
                  }}
                  className="block rounded-md px-3 py-2 text-base font-medium text-gray-400 hover:bg-gray-700 hover:text-white"
                >
                  Sign Out
                </button>
              </div>
            </div>
          </div>
        </>
      </div>

      {/* <header className="bg-white shadow">
        <div className="mx-auto max-w-7xl px-4 py-6 ">
          <h1 className="text-3xl font-bold tracking-tight text-gray-900">Dashboard</h1>
        </div>
      </header> */}
      {/* <main>
        <div className="mx-auto max-w-7xl py-6 sm:px-6 lg:px-8">
          Content
        </div>
      </main> */}
    </div>
  )
}
