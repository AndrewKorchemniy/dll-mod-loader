use std::ffi::CString;
use std::fs;
use std::io::{self, Error, ErrorKind};
use std::ptr;
use std::vec::Vec;
use dll_injector::inject_dll_load_library;
use winapi::um::processthreadsapi::ResumeThread;
use winapi::um::handleapi::CloseHandle;
use winapi::um::winbase::CREATE_SUSPENDED;
use winapi::um::processthreadsapi::PROCESS_INFORMATION;
use winapi::um::processthreadsapi::STARTUPINFOA;
use winapi::um::processthreadsapi::CreateProcessA;

pub struct ModLoader {
    process_info: PROCESS_INFORMATION,
    mod_dlls: Vec<String>,
}

impl ModLoader {
    pub fn new(game_executable: &str) -> io::Result<Self> {
        if !fs::exists(game_executable)? {
            return Err(Error::new(ErrorKind::NotFound, "Game executable not found."));
        }

        let mut si: STARTUPINFOA = unsafe { std::mem::zeroed() };
        let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

        // Create the process in suspended state
        if unsafe {
            CreateProcessA(
                ptr::null(),
                CString::new(game_executable).unwrap().into_raw(),
                ptr::null_mut(),
                ptr::null_mut(),
                1, // TRUE
                CREATE_SUSPENDED,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut si,
                &mut pi,
            )
        } == 0
        {
            return Err(Error::last_os_error());
        }

        Ok(ModLoader {
            process_info: pi,
            mod_dlls: Vec::new(),
        })
    }

    pub fn load_mods(&mut self, mods_directory: &str) -> io::Result<()> {
        let mod_paths = fs::read_dir(mods_directory)?
            .filter_map(|entry| {
                let path = entry.ok()?.path();
                if path.extension()?.to_str()? == "dll" {
                    Some(path.display().to_string())
                } else {
                    None
                }
            })
            .collect::<Vec<String>>();

        self.mod_dlls = mod_paths;

        for dll in &self.mod_dlls {
            inject_dll_load_library(self.process_info.dwProcessId, &dll).unwrap();
        }

        Ok(())
    }

    pub fn resume_process(&self) {
        unsafe { ResumeThread(self.process_info.hThread) };
    }
}

impl Drop for ModLoader {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.process_info.hProcess);
            CloseHandle(self.process_info.hThread);
        }
    }
}
