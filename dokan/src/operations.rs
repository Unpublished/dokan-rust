use std::ffi::c_void;
use std::slice;

use dokan_sys::{
	win32::{FILE_OPEN_IF, FILE_OVERWRITE_IF, FILE_SUPERSEDE},
	PFillFindData, PFillFindStreamData, PDOKAN_FILE_INFO, PDOKAN_IO_SECURITY_CONTEXT,
};
use widestring::U16CStr;
use windows_sys::Win32::Foundation::{BOOL, FILETIME, NTSTATUS, STATUS_BUFFER_OVERFLOW, STATUS_OBJECT_NAME_COLLISION, TRUE};
use windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION;

use crate::{
	data::{wrap_fill_data, OperationInfo},
	file_system_handler::FileSystemHandler,
	operations_helpers::{wrap_nt_result, wrap_unit, NtResult},
};

pub extern "stdcall" fn create_file<'c, 'h: 'c, FSH: FileSystemHandler<'c, 'h> + 'h>(
	file_name: *const u16,
	security_context: PDOKAN_IO_SECURITY_CONTEXT,
	desired_access: u32,
	file_attributes: u32,
	share_access: u32,
	create_disposition: u32,
	create_options: u32,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	wrap_nt_result(|| unsafe {
		let file_name = U16CStr::from_ptr_str(file_name);
		let mut info = OperationInfo::<'c, 'h, FSH>::new(dokan_file_info);
		info.drop_context();
		info.handler()
			.create_file(
				file_name,
				&*security_context,
				desired_access,
				file_attributes,
				share_access,
				create_disposition,
				create_options,
				&mut info,
			)
			.and_then(|create_info| {
				(&mut *dokan_file_info).Context =
					Box::into_raw(Box::new(create_info.context)) as u64;
				(&mut *dokan_file_info).IsDirectory = create_info.is_dir.into();
				if (create_disposition == FILE_OPEN_IF
					|| create_disposition == FILE_OVERWRITE_IF
					|| create_disposition == FILE_SUPERSEDE)
					&& !create_info.new_file_created
				{
					Err(STATUS_OBJECT_NAME_COLLISION)
				} else {
					Ok(())
				}
			})
	})
}

pub extern "stdcall" fn cleanup<'c, 'h: 'c, FSH: FileSystemHandler<'c, 'h> + 'h>(
	file_name: *const u16,
	dokan_file_info: PDOKAN_FILE_INFO,
) {
	wrap_unit(|| unsafe {
		let file_name = U16CStr::from_ptr_str(file_name);
		let info = OperationInfo::<'c, 'h, FSH>::new(dokan_file_info);
		info.handler().cleanup(file_name, &info, info.context());
	});
}

pub extern "stdcall" fn close_file<'c, 'h: 'c, FSH: FileSystemHandler<'c, 'h> + 'h>(
	file_name: *const u16,
	dokan_file_info: PDOKAN_FILE_INFO,
) {
	wrap_unit(|| unsafe {
		let file_name = U16CStr::from_ptr_str(file_name);
		let mut info = OperationInfo::<'c, 'h, FSH>::new(dokan_file_info);
		info.handler().close_file(file_name, &info, info.context());
		info.drop_context();
	});
}

pub extern "stdcall" fn read_file<'c, 'h: 'c, FSH: FileSystemHandler<'c, 'h> + 'h>(
	file_name: *const u16,
	buffer: *mut c_void,
	buffer_length: u32,
	read_length: *mut u32,
	offset: i64,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	wrap_nt_result(|| unsafe {
		*read_length = 0;
		let file_name = U16CStr::from_ptr_str(file_name);
		let info = OperationInfo::<'c, 'h, FSH>::new(dokan_file_info);
		let buffer = slice::from_raw_parts_mut(buffer as *mut _, buffer_length as usize);
		info.handler()
			.read_file(file_name, offset, buffer, &info, info.context())
			.map(|bytes_read| {
				*read_length = bytes_read;
			})
	})
}

pub extern "stdcall" fn write_file<'c, 'h: 'c, FSH: FileSystemHandler<'c, 'h> + 'h>(
	file_name: *const u16,
	buffer: *const c_void,
	number_of_bytes_to_write: u32,
	number_of_bytes_written: *mut u32,
	offset: i64,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	wrap_nt_result(|| unsafe {
		*number_of_bytes_written = 0;
		let file_name = U16CStr::from_ptr_str(file_name);
		let info = OperationInfo::<'c, 'h, FSH>::new(dokan_file_info);
		let buffer = slice::from_raw_parts(buffer as *mut _, number_of_bytes_to_write as usize);
		info.handler()
			.write_file(file_name, offset, buffer, &info, info.context())
			.map(|bytes_written| {
				*number_of_bytes_written = bytes_written;
			})
	})
}

pub extern "stdcall" fn flush_file_buffers<'c, 'h: 'c, FSH: FileSystemHandler<'c, 'h> + 'h>(
	file_name: *const u16,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	wrap_nt_result(|| unsafe {
		let file_name = U16CStr::from_ptr_str(file_name);
		let info = OperationInfo::<'c, 'h, FSH>::new(dokan_file_info);
		info.handler()
			.flush_file_buffers(file_name, &info, info.context())
	})
}

pub extern "stdcall" fn get_file_information<'c, 'h: 'c, FSH: FileSystemHandler<'c, 'h> + 'h>(
	file_name: *const u16,
	buffer: *mut BY_HANDLE_FILE_INFORMATION,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	wrap_nt_result(|| unsafe {
		let file_name = U16CStr::from_ptr_str(file_name);
		let info = OperationInfo::<'c, 'h, FSH>::new(dokan_file_info);
		info.handler()
			.get_file_information(file_name, &info, info.context())
			.map(|file_info| {
				*buffer = file_info.to_raw_struct();
			})
	})
}

pub extern "stdcall" fn find_files<'c, 'h: 'c, FSH: FileSystemHandler<'c, 'h> + 'h>(
	file_name: *const u16,
	fill_find_data: PFillFindData,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	wrap_nt_result(|| unsafe {
		let file_name = U16CStr::from_ptr_str(file_name);
		let fill_wrapper = wrap_fill_data(fill_find_data, dokan_file_info, 0);
		let info = OperationInfo::<'c, 'h, FSH>::new(dokan_file_info);
		info.handler()
			.find_files(file_name, fill_wrapper, &info, info.context())
	})
}

pub extern "stdcall" fn find_files_with_pattern<'c, 'h: 'c, FSH: FileSystemHandler<'c, 'h> + 'h>(
	file_name: *const u16,
	search_pattern: *const u16,
	fill_find_data: PFillFindData,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	wrap_nt_result(|| unsafe {
		let file_name = U16CStr::from_ptr_str(file_name);
		let search_pattern = U16CStr::from_ptr_str(search_pattern);
		let fill_wrapper = wrap_fill_data(fill_find_data, dokan_file_info, 0);
		let info = OperationInfo::<'c, 'h, FSH>::new(dokan_file_info);
		info.handler().find_files_with_pattern(
			file_name,
			search_pattern,
			fill_wrapper,
			&info,
			info.context(),
		)
	})
}

pub extern "stdcall" fn set_file_attributes<'c, 'h: 'c, FSH: FileSystemHandler<'c, 'h> + 'h>(
	file_name: *const u16,
	file_attributes: u32,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	wrap_nt_result(|| unsafe {
		let file_name = U16CStr::from_ptr_str(file_name);
		let info = OperationInfo::<'c, 'h, FSH>::new(dokan_file_info);
		info.handler()
			.set_file_attributes(file_name, file_attributes, &info, info.context())
	})
}

pub extern "stdcall" fn set_file_time<'c, 'h: 'c, FSH: FileSystemHandler<'c, 'h> + 'h>(
	file_name: *const u16,
	creation_time: *const FILETIME,
	last_access_time: *const FILETIME,
	last_write_time: *const FILETIME,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	wrap_nt_result(|| unsafe {
		let file_name = U16CStr::from_ptr_str(file_name);
		let info = OperationInfo::<'c, 'h, FSH>::new(dokan_file_info);
		info.handler().set_file_time(
			file_name,
			creation_time.into(),
			last_access_time.into(),
			last_write_time.into(),
			&info,
			info.context(),
		)
	})
}

pub extern "stdcall" fn delete_file<'c, 'h: 'c, FSH: FileSystemHandler<'c, 'h> + 'h>(
	file_name: *const u16,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	wrap_nt_result(|| unsafe {
		let file_name = U16CStr::from_ptr_str(file_name);
		let info = OperationInfo::<'c, 'h, FSH>::new(dokan_file_info);
		info.handler().delete_file(file_name, &info, info.context())
	})
}

pub extern "stdcall" fn delete_directory<'c, 'h: 'c, FSH: FileSystemHandler<'c, 'h> + 'h>(
	file_name: *const u16,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	wrap_nt_result(|| unsafe {
		let file_name = U16CStr::from_ptr_str(file_name);
		let info = OperationInfo::<'c, 'h, FSH>::new(dokan_file_info);
		info.handler()
			.delete_directory(file_name, &info, info.context())
	})
}

pub extern "stdcall" fn move_file<'c, 'h: 'c, FSH: FileSystemHandler<'c, 'h> + 'h>(
	file_name: *const u16,
	new_file_name: *const u16,
	replace_if_existing: BOOL,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	wrap_nt_result(|| unsafe {
		let file_name = U16CStr::from_ptr_str(file_name);
		let new_file_name = U16CStr::from_ptr_str(new_file_name);
		let info = OperationInfo::<'c, 'h, FSH>::new(dokan_file_info);
		info.handler().move_file(
			file_name,
			new_file_name,
			replace_if_existing == TRUE,
			&info,
			info.context(),
		)
	})
}

pub extern "stdcall" fn set_end_of_file<'c, 'h: 'c, FSH: FileSystemHandler<'c, 'h> + 'h>(
	file_name: *const u16,
	byte_offset: i64,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	wrap_nt_result(|| unsafe {
		let file_name = U16CStr::from_ptr_str(file_name);
		let info = OperationInfo::<'c, 'h, FSH>::new(dokan_file_info);
		info.handler()
			.set_end_of_file(file_name, byte_offset, &info, info.context())
	})
}

pub extern "stdcall" fn set_allocation_size<'c, 'h: 'c, FSH: FileSystemHandler<'c, 'h> + 'h>(
	file_name: *const u16,
	alloc_size: i64,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	wrap_nt_result(|| unsafe {
		let file_name = U16CStr::from_ptr_str(file_name);
		let info = OperationInfo::<'c, 'h, FSH>::new(dokan_file_info);
		info.handler()
			.set_allocation_size(file_name, alloc_size, &info, info.context())
	})
}

// Extern stdcall functions with similar bodies but not called directly with trigger a compiler bug when built in
// release mode. It seems that extracting the function bodies into a common function works around this bug.
// See https://github.com/rust-lang/rust/issues/72212
fn lock_unlock_file<'c, 'h: 'c, FSH: FileSystemHandler<'c, 'h> + 'h>(
	file_name: *const u16,
	byte_offset: i64,
	length: i64,
	dokan_file_info: PDOKAN_FILE_INFO,
	func: fn(
		&'h FSH,
		&U16CStr,
		i64,
		i64,
		&OperationInfo<'c, 'h, FSH>,
		&'c FSH::Context,
	) -> NtResult,
) -> NTSTATUS {
	wrap_nt_result(|| unsafe {
		let file_name = U16CStr::from_ptr_str(file_name);
		let info = OperationInfo::<'c, 'h, FSH>::new(dokan_file_info);
		func(
			info.handler(),
			file_name,
			byte_offset,
			length,
			&info,
			info.context(),
		)
	})
}

pub extern "stdcall" fn lock_file<'c, 'h: 'c, FSH: FileSystemHandler<'c, 'h> + 'h>(
	file_name: *const u16,
	byte_offset: i64,
	length: i64,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	lock_unlock_file(
		file_name,
		byte_offset,
		length,
		dokan_file_info,
		FSH::lock_file,
	)
}

pub extern "stdcall" fn unlock_file<'c, 'h: 'c, FSH: FileSystemHandler<'c, 'h> + 'h>(
	file_name: *const u16,
	byte_offset: i64,
	length: i64,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	lock_unlock_file(
		file_name,
		byte_offset,
		length,
		dokan_file_info,
		FSH::unlock_file,
	)
}

pub extern "stdcall" fn get_disk_free_space<'c, 'h: 'c, FSH: FileSystemHandler<'c, 'h> + 'h>(
	free_bytes_available: *mut u64,
	total_number_of_bytes: *mut u64,
	total_number_of_free_bytes: *mut u64,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	wrap_nt_result(|| {
		let info = OperationInfo::<'c, 'h, FSH>::new(dokan_file_info);
		info.handler()
			.get_disk_free_space(&info)
			.map(|space_info| unsafe {
				if !free_bytes_available.is_null() {
					*free_bytes_available = space_info.available_byte_count;
				}
				if !total_number_of_bytes.is_null() {
					*total_number_of_bytes = space_info.byte_count;
				}
				if !total_number_of_free_bytes.is_null() {
					*total_number_of_free_bytes = space_info.free_byte_count;
				}
			})
	})
}

pub extern "stdcall" fn get_volume_information<'c, 'h: 'c, FSH: FileSystemHandler<'c, 'h> + 'h>(
	volume_name_buffer: *mut u16,
	volume_name_size: u32,
	volume_serial_number: *mut u32,
	maximum_component_length: *mut u32,
	file_system_flags: *mut u32,
	file_system_name_buffer: *mut u16,
	file_system_name_size: u32,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	wrap_nt_result(|| {
		let info = OperationInfo::<'c, 'h, FSH>::new(dokan_file_info);
		info.handler()
			.get_volume_information(&info)
			.map(|volume_info| unsafe {
				volume_name_buffer.copy_from_nonoverlapping(
					volume_info.name.as_ptr(),
					(volume_info.name.len() + 1).min(volume_name_size as usize),
				);
				if !volume_serial_number.is_null() {
					*volume_serial_number = volume_info.serial_number;
				}
				if !maximum_component_length.is_null() {
					*maximum_component_length = volume_info.max_component_length;
				}
				if !file_system_flags.is_null() {
					*file_system_flags = volume_info.fs_flags;
				}
				file_system_name_buffer.copy_from_nonoverlapping(
					volume_info.fs_name.as_ptr(),
					(volume_info.fs_name.len() + 1).min(file_system_name_size as usize),
				);
			})
	})
}

pub extern "stdcall" fn mounted<'c, 'h: 'c, FSH: FileSystemHandler<'c, 'h> + 'h>(
	mount_point: *const u16,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	wrap_nt_result(|| unsafe {
		let mount_point = U16CStr::from_ptr_str(mount_point);
		let info = OperationInfo::<'c, 'h, FSH>::new(dokan_file_info);
		info.handler().mounted(mount_point, &info)
	})
}

pub extern "stdcall" fn unmounted<'c, 'h: 'c, FSH: FileSystemHandler<'c, 'h> + 'h>(
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	wrap_nt_result(|| {
		let info = OperationInfo::<'c, 'h, FSH>::new(dokan_file_info);
		info.handler().unmounted(&info)
	})
}

pub extern "stdcall" fn get_file_security<'c, 'h: 'c, FSH: FileSystemHandler<'c, 'h> + 'h>(
	file_name: *const u16,
	security_information: *mut u32,
	security_descriptor: *mut c_void,
	buffer_length: u32,
	length_needed: *mut u32,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	wrap_nt_result(|| unsafe {
		let file_name = U16CStr::from_ptr_str(file_name);
		let info = OperationInfo::<'c, 'h, FSH>::new(dokan_file_info);
		info.handler()
			.get_file_security(
				file_name,
				*security_information,
				security_descriptor,
				buffer_length,
				&info,
				info.context(),
			)
			.and_then(|needed| {
				*length_needed = needed;
				if needed <= buffer_length {
					Ok(())
				} else {
					Err(STATUS_BUFFER_OVERFLOW)
				}
			})
	})
}

pub extern "stdcall" fn set_file_security<'c, 'h: 'c, FSH: FileSystemHandler<'c, 'h> + 'h>(
	file_name: *const u16,
	security_information: *mut u32,
	security_descriptor: *mut c_void,
	buffer_length: u32,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	wrap_nt_result(|| unsafe {
		let file_name = U16CStr::from_ptr_str(file_name);
		let info = OperationInfo::<'c, 'h, FSH>::new(dokan_file_info);
		info.handler().set_file_security(
			file_name,
			*security_information,
			security_descriptor,
			buffer_length,
			&info,
			info.context(),
		)
	})
}

pub extern "stdcall" fn find_streams<'c, 'h: 'c, FSH: FileSystemHandler<'c, 'h> + 'h>(
	file_name: *const u16,
	fill_find_stream_data: PFillFindStreamData,
	find_stream_context: *mut c_void,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	wrap_nt_result(|| unsafe {
		let file_name = U16CStr::from_ptr_str(file_name);
		let fill_wrapper = wrap_fill_data(fill_find_stream_data, find_stream_context, 1);
		let info = OperationInfo::<'c, 'h, FSH>::new(dokan_file_info);
		info.handler()
			.find_streams(file_name, fill_wrapper, &info, info.context())
	})
}
