use std::{array, intrinsics::transmute, iter, ptr};

use winapi::{
    shared::{
        minwindef::LPVOID,
        winerror::WAIT_TIMEOUT,
    },
    um::{
        errhandlingapi::GetLastError,
        handleapi::CloseHandle,
        libloaderapi::{GetModuleHandleA, GetProcAddress},
        memoryapi::{VirtualAllocEx, VirtualFreeEx, WriteProcessMemory},
        processthreadsapi::{CreateRemoteThread, OpenProcess},
        synchapi::WaitForSingleObject,
        winbase::{INFINITE, WAIT_ABANDONED, WAIT_FAILED, WAIT_OBJECT_0},
        winnt::{HANDLE, MEM_COMMIT, MEM_RELEASE, PAGE_READWRITE, PROCESS_ALL_ACCESS},
    },
};

#[cfg(not(target_os = "windows"))]
compile_error!("windows only");

#[derive(Debug)]
enum LoadLibraryError {
    PathTooLong,
    OpenProcess { winapi_error: u32 },
    AllocMemory { winapi_error: u32 },
    WriteArg { winapi_error: u32 },
    NotEnoughBytesWritten { bytes_written: usize },
    FreeArgumentMemory { winapi_error: u32 },
    // https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject
    ThreadWaitAbandoned,                    // WAIT_ABANDONED
    ThreadWaitTimeout,                      // WAIT_TIMEOUT
    ThreadWaitFailed { winapi_error: u32 }, // WAIT_FAILED
    ThreadWaitUnknown { return_code: u32 }, // other error than specified above
}

fn main() {
    println!("Hello, world!");

    unsafe {
        // todo: handle program args
        inject(
            18488,
            &WString::from(
                "C:\\Users\\makin\\Documents\\buzkaaclicker\\agentvc\\x64\\Debug\\agent.dll",
            ),
        )
        .unwrap()
    }
}

#[derive(Debug)]
struct WString {
    bytes: Vec<u8>,
}

impl WString {
    fn bytes_length(&self) -> usize {
        self.bytes.len()
    }
}

impl From<&str> for WString {
    fn from(val: &str) -> Self {
        WString {
            bytes: val
                .encode_utf16()
                .map(u16::to_ne_bytes) // convert to bytes vec
                .flat_map(array::IntoIter::new)
                .chain(iter::once(0)) // convert to cstring (add \0 suffix)
                .collect::<Vec<u8>>(),
        }
    }
}

// Create handle to given process. Then allocate and fill "path" bytes in target process,
// start new remote thread with entry point at LoadLibraryW
unsafe fn inject(process_id: u32, path: &WString) -> Result<(), LoadLibraryError> {
    const MAX_UNICODE_PATH: u16 = u16::MAX;
    if path.bytes_length() >= MAX_UNICODE_PATH as usize {
        return Err(LoadLibraryError::PathTooLong);
    }

    // We need to create handle to achieve permissions to allocate, write, create thread in target process.
    let process_handle = OpenProcess(PROCESS_ALL_ACCESS, 0, process_id);
    if process_handle as usize == 0 {
        return Err(LoadLibraryError::OpenProcess {
            winapi_error: GetLastError(),
        });
    }

    let load_library_result = load_library(process_handle, &path);
    // close handle, it's no longer used
    CloseHandle(process_handle);
    load_library_result
}

unsafe fn load_library(process_handle: HANDLE, path: &WString) -> Result<(), LoadLibraryError> {
    // allocate memory in target process which later will be filled with our path
    let path_address = VirtualAllocEx(
        process_handle,
        ptr::null_mut(),
        path.bytes_length(),
        MEM_COMMIT,
        PAGE_READWRITE,
    );
    if path_address as usize == 0 {
        return Err(LoadLibraryError::AllocMemory {
            winapi_error: GetLastError(),
        });
    }

    let result = load_library_allocated_arg(process_handle, path, path_address);
    // free memory, it's no longer needed
    if VirtualFreeEx(process_handle, path_address, 0, MEM_RELEASE) == 0 {
        return Err(LoadLibraryError::FreeArgumentMemory {
            winapi_error: GetLastError(),
        });
    }
    result
}

unsafe fn load_library_allocated_arg(
    process_handle: HANDLE,
    path: &WString,
    path_address: LPVOID,
) -> Result<(), LoadLibraryError> {
    let mut bytes_written: usize = 0;
    // write path which will be used as an argument in LoadLibraryW
    let write_arg_failure = WriteProcessMemory(
        process_handle,
        path_address,
        path.bytes.as_ptr() as _,
        path.bytes_length(),
        &mut bytes_written,
    ) == 0;

    if write_arg_failure {
        return Err(LoadLibraryError::WriteArg {
            winapi_error: GetLastError(),
        });
    }

    if bytes_written < path.bytes_length() {
        return Err(LoadLibraryError::NotEnoughBytesWritten {
            bytes_written: bytes_written as usize,
        });
    }

    let kernel32_handle = GetModuleHandleA("kernel32\0".as_ptr() as _);
    let load_libraryw_address = GetProcAddress(kernel32_handle, "LoadLibraryW\0".as_ptr() as _);

    // Start thread at LoadLibraryW address with "path_address" as an argument.
    let thread_handle = CreateRemoteThread(
        process_handle,
        ptr::null_mut(),
        0,
        Some(transmute(load_libraryw_address)),
        path_address,
        0,
        ptr::null_mut(),
    );
    let wait_result = WaitForSingleObject(thread_handle, INFINITE);
    CloseHandle(thread_handle);
    match wait_result {
        WAIT_OBJECT_0 => Ok(()),
        WAIT_ABANDONED => Err(LoadLibraryError::ThreadWaitAbandoned),
        WAIT_TIMEOUT => Err(LoadLibraryError::ThreadWaitTimeout),
        WAIT_FAILED => Err(LoadLibraryError::ThreadWaitFailed {
            winapi_error: GetLastError(),
        }),
        unknown => Err(LoadLibraryError::ThreadWaitUnknown {
            return_code: unknown,
        }),
    }
}
