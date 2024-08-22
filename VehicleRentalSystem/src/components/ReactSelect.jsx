import { FieldProps } from "formik";
import React from "react";
import Select, { Options } from "react-select";

export const ReactSelect = ({
    className,
    placeholder,
    field,
    form,
    options,
    isMulti = false
}) => {

    const onChange = (option) => {
        form.setFieldValue(
            field.name,
            isMulti
                ? (option).map((item) => item.value)
                : (option).value
        );
    };

    const getValue = () => {
        if (options) {
            return isMulti
                ? options.filter((option) => field?.value?.indexOf(option.value) >= 0)
                : options.find((option) => option?.value === field?.value);
        } else {
            return isMulti ? [] : "";
        }
    };

    return (
        <Select
            styles={{
                menuPortal: base => ({ ...base, zIndex: 9999 })
            }}
            menuPortalTarget={document.body}
            className={className}
            name={field.name}
            value={getValue()}
            onChange={onChange}
            placeholder={placeholder}
            options={options}
            isMulti={isMulti}
        />
    );
};

export default ReactSelect;