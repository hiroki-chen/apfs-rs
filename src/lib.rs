#![cfg_attr(not(any(feature = "std", test)), no_std)]

#![feature(iter_advance_by)]

extern crate alloc;

pub mod apfs;
pub mod meta;

pub type KResult<T> = Result<T, Errno>;

/// Unix standard error codes.
///
/// The `perror` tool can be used to find the error message which is associated with a given error code.
#[derive(Copy, Clone, Debug, PartialEq, PartialOrd)]
pub enum Errno {
    EPERM = 1,
    ENOENT,
    ESRCH,
    EINTR,
    EIO,
    ENXIO,
    E2BIG,
    ENOEXEC,
    EBADF,
    ECHILD,
    EAGAIN,
    ENOMEM,
    EACCES,
    EFAULT,
    ENOTBLK,
    EBUSY,
    EEXIST,
    EXDEV,
    ENODEV,
    ENOTDIR,
    EISDIR,
    EINVAL,
    ENFILE,
    EMFILE,
    ENOTTY,
    ETXTBSY,
    EFBIG,
    ENOSPC,
    ESPIPE,
    EROFS,
    EMLINK,
    EPIPE,
    EDOM,
    ERANGE,
    EWOULDBLOCK,
}
