use std::mem;
use std::os::raw::c_void;

const CMSG_BUF: usize = 64; // >= CMSG_SPACE(sizeof(i32))

pub fn send_fd(sock: i32, fd: i32) -> isize {
    unsafe {
        let mut byte: u8 = 1;
        let mut iov = libc::iovec {
            iov_base: &mut byte as *mut u8 as *mut c_void,
            iov_len: 1,
        };
        let mut cbuf = [0u8; CMSG_BUF];
        let mut msg: libc::msghdr = mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.as_mut_ptr() as *mut c_void;
        msg.msg_controllen = libc::CMSG_SPACE(mem::size_of::<i32>() as u32) as _;

        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(mem::size_of::<i32>() as u32) as _;
        std::ptr::copy_nonoverlapping(
            &fd as *const i32 as *const u8,
            libc::CMSG_DATA(cmsg),
            mem::size_of::<i32>(),
        );

        libc::sendmsg(sock, &msg, libc::MSG_NOSIGNAL)
    }
}

pub fn recv_fd(sock: i32) -> i32 {
    unsafe {
        let mut byte: u8 = 0;
        let mut iov = libc::iovec {
            iov_base: &mut byte as *mut u8 as *mut c_void,
            iov_len: 1,
        };
        let mut cbuf = [0u8; CMSG_BUF];
        let mut msg: libc::msghdr = mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.as_mut_ptr() as *mut c_void;
        msg.msg_controllen = CMSG_BUF as _;

        let n = libc::recvmsg(sock, &mut msg, 0);
        if n <= 0 {
            return -1;
        }
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() || (*cmsg).cmsg_type != libc::SCM_RIGHTS {
            return -1;
        }
        let mut fd: i32 = -1;
        std::ptr::copy_nonoverlapping(
            libc::CMSG_DATA(cmsg),
            &mut fd as *mut i32 as *mut u8,
            mem::size_of::<i32>(),
        );
        fd
    }
}
