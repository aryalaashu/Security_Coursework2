import React from 'react'

function FieldError({ message }) {
    return (
        <>
            {
                message &&
                <div className='error'>{message}</div>
            }
        </>
    )
}

export default FieldError