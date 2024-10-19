use std::{ ffi::CString, fs, io, path::Path, ptr };
use std::collections::HashSet;
use thiserror::Error;
use winapi::um::{
    handleapi::CloseHandle,
    processthreadsapi::{ ResumeThread, PROCESS_INFORMATION, STARTUPINFOA, CreateProcessA },
    winbase::CREATE_SUSPENDED,
};

#[derive(Error, Debug)]
pub enum ModLoaderError {
    #[error("Executable not found: {0}")] ExecutableNotFound(String),

    #[error(
        "Executable size mismatch. Expected {expected} bytes but found {found} bytes."
    )] ExecutableSizeMismatch {
        expected: u64,
        found: u64,
    },

    #[error("Failed to create the process: {0}")] ProcessCreationFailed(#[source] io::Error),

    #[error("Failed to inject DLL: {0}")] DllInjectionFailed(String),

    #[error("Failed to resume the process thread: {0}")] ResumeThreadFailed(#[source] io::Error),

    #[error("Failed to read mods directory: {0}")] DirectoryReadFailed(#[source] io::Error),
}

pub struct ModLoader {
    process_info: Option<PROCESS_INFORMATION>,
    mod_dlls: HashSet<String>,
}

impl ModLoader {
    pub fn new() -> Self {
        Self {
            process_info: None,
            mod_dlls: HashSet::new(),
        }
    }

    /// Creates a process in a suspended state.
    pub fn create_suspended_process(
        &mut self,
        executable: impl AsRef<Path>,
        expected_size: Option<u64>
    ) -> Result<(), ModLoaderError> {
        let executable = executable.as_ref();

        // Check if the executable exists
        if !executable.exists() {
            return Err(
                ModLoaderError::ExecutableNotFound(executable.to_string_lossy().to_string())
            );
        }

        // Validate the executable size
        if let Some(expected_size) = expected_size {
            let metadata = fs
                ::metadata(executable)
                .map_err(|e|
                    ModLoaderError::ProcessCreationFailed(
                        io::Error::new(io::ErrorKind::InvalidData, e)
                    )
                )?;
            let actual_size = metadata.len();

            if actual_size != expected_size {
                return Err(ModLoaderError::ExecutableSizeMismatch {
                    expected: expected_size,
                    found: actual_size,
                });
            }
        }

        let mut si: STARTUPINFOA = unsafe { std::mem::zeroed() };
        let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

        // Create the process in a suspended state
        let result = unsafe {
            CreateProcessA(
                ptr::null(),
                CString::new(executable.to_string_lossy().as_bytes()).unwrap().into_raw(),
                ptr::null_mut(),
                ptr::null_mut(),
                1, // TRUE
                CREATE_SUSPENDED,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut si,
                &mut pi
            )
        };

        if result == 0 {
            return Err(ModLoaderError::ProcessCreationFailed(io::Error::last_os_error()));
        }

        println!("Created process with PID: {}", pi.dwProcessId);
        self.process_info = Some(pi);
        Ok(())
    }

    /// Loads all DLL files in the specified directory.
    pub fn load_mods(&mut self, mods_directory: impl AsRef<Path>) -> Result<(), ModLoaderError> {
        let mods_directory = mods_directory.as_ref();
        if !mods_directory.exists() || !mods_directory.is_dir() {
            return Err(
                ModLoaderError::DirectoryReadFailed(
                    io::Error::new(io::ErrorKind::NotFound, "Mods directory not found or invalid")
                )
            );
        }

        let mod_paths = fs
            ::read_dir(mods_directory)
            .map_err(ModLoaderError::DirectoryReadFailed)?
            .filter_map(|entry| {
                entry.ok().and_then(|e| {
                    let path = e.path();
                    if path.extension()?.to_str()? == "dll" {
                        Some(path.to_string_lossy().to_string())
                    } else {
                        None
                    }
                })
            });

        self.mod_dlls = mod_paths.collect();
        Ok(())
    }

    /// Injects all loaded mods into the process.
    pub fn inject_mods(&self) -> Result<(), ModLoaderError> {
        if let Some(pi) = &self.process_info {
            for dll in &self.mod_dlls {
                println!("Injecting {}...", dll);
                let result = dll_injector::inject_dll_load_library(pi.dwProcessId, dll);
                if let Err(e) = result {
                    println!("Failed to inject {}: {}", dll, e);
                    return Err(ModLoaderError::DllInjectionFailed(dll.clone()));
                }
            }
            Ok(())
        } else {
            Err(
                ModLoaderError::ProcessCreationFailed(
                    io::Error::new(io::ErrorKind::NotConnected, "Process not initialized")
                )
            )
        }
    }

    /// Resumes the process thread.
    pub fn resume_process(&self) -> Result<(), ModLoaderError> {
        if let Some(pi) = &self.process_info {
            let result = unsafe { ResumeThread(pi.hThread) };
            if result == u32::MAX {
                return Err(ModLoaderError::ResumeThreadFailed(io::Error::last_os_error()));
            }
            println!("Process resumed.");
            Ok(())
        } else {
            Err(
                ModLoaderError::ProcessCreationFailed(
                    io::Error::new(io::ErrorKind::NotConnected, "Process not initialized")
                )
            )
        }
    }
}

impl Drop for ModLoader {
    fn drop(&mut self) {
        if let Some(pi) = &self.process_info {
            unsafe {
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
            }
        }
    }
}
