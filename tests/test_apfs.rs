use std::{io::Read, sync::Arc};

use apfs_rs::{
    apfs::{AppleFileSystem, Device},
    meta::{calc_fletcher64, NxSuperBlock, ObjectPhysical, NX_MAGIC},
};

#[test]
fn test_open_image() {
    let _ = std::fs::File::open(format!("{}/test-apfs.img", env!("CARGO_MANIFEST_DIR"))).unwrap();
}

#[test]
fn test_fletcher() {
    std::env::set_var("RUST_LOG", "info");
    env_logger::init();

    let mut apfs =
        std::fs::File::open(format!("{}/test-apfs.img", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let mut vec = Vec::new();
    apfs.read_to_end(&mut vec).unwrap();

    // Convert the endianness
    let apfs_vec = &vec[8..4096];
    let checksum = calc_fletcher64(apfs_vec).unwrap().to_le_bytes();
    println!(
        "checksum = {:x?}; correct: {:x?}",
        checksum,
        &vec[..core::mem::size_of::<ObjectPhysical>()]
    );
}

#[test]
fn test_apfs_mount() {
    std::env::set_var("RUST_LOG", "info");
    env_logger::init();

    let mut apfs =
        std::fs::File::open(format!("{}/test-apfs.img", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let mut vec = Vec::new();
    apfs.read_to_end(&mut vec).unwrap();

    let apfs = AppleFileSystem::mount(Arc::new(vec));

    assert!(apfs.is_ok());

    // Load its B-Tree.
    let apfs = apfs.unwrap();
    apfs.load_object_map().unwrap();
    apfs.mount_volumns_all().unwrap();
    apfs.read_apfs_trees().unwrap();
}
