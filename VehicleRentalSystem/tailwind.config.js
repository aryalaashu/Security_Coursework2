/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/**/*.{js,jsx,ts,tsx}",
  ],
  theme: {
    btn: {
      'current': 'py-2 px-4 bg-current text-white font-semibold rounded-lg shadow-md hover:bg-opacity-80 focus:outline-none focus:ring-2 focus:ring-red-500 focus:ring-offset-2 focus:ring-offset-red-200',
    },
    extend: {
      colors: {
        current: '#473BF0',
        secondary: '#F4F7FA',
      },

    },
  },
  plugins: [],
}