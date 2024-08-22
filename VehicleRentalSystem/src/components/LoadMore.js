
import React  from 'react'
import { BiChevronDown, BiLoader } from 'react-icons/bi'

function LoadMore({ page, setPage, totalPage, loading, setLoading }) {
    return (
        <>
            {
                (page !== totalPage || loading) &&
                <div className='my-10 flex items-center text-center justify-center w-full' >
                    <button className='items-center flex gap-3 bg-green-600 p-3 rounded-md px-4 text-sm text-white font-semibold' onClick={() => {
                        setPage(page + 1)
                        setLoading(true)
                    }}> <span>{!loading ? <BiChevronDown /> : <BiLoader className='animate-spin' />} </span> Load More</button>
                </div>
            }
        </>
    )
}

export default LoadMore