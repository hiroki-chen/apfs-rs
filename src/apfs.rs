use alloc::{string::String, sync::Arc, vec, vec::Vec};
use log::{error, info};
use rcore_fs::{
    dirty::Dirty as MaybeDirty,
    vfs::{FileSystem, INode},
};
use spin::RwLock;

use crate::{
    meta::{
        calc_fletcher64, ApfsSuperblock, BTreeInfo, BTreeNodeFlags, BTreeNodePhysical,
        CheckpointMapPhysical, NxSuperBlock, ObjectMap, ObjectMapKey, ObjectMapPhysical,
        ObjectPhysical, ObjectTypes, Oid, BLOCK_SIZE,
    },
    Errno, KResult,
};

/// Denotes the disk driver backend the filesystem uses.
pub trait Device: Send + Sync {
    /// Reads a buffer at a given offset of the disk and returns the size successfully read.
    fn read_buf_at(&self, offset: usize, buf: &mut [u8]) -> KResult<usize>;

    /// Reads a buffer at a given offset of the disk and returns the size successfully written.
    fn write_buf_at(&self, offset: usize, buf: &[u8]) -> KResult<usize>;

    /// Synchronizes the memory and the disk content.
    fn sync(&self) -> KResult<()>;
}

/// Allows us to access the disk in a block-like way.
pub trait BlockLike: Device {
    fn load_struct<T>(&self, id: Oid) -> KResult<T>
    where
        T: AsRef<[u8]> + AsMut<[u8]> + Clone + Sized + 'static,
    {
        unsafe {
            let mut buf = vec![0u8; core::mem::size_of::<T>()];

            self.read_block(id, 0, &mut buf)?;
            info!("this is {:x?}", buf);

            Ok((&*(buf.as_ptr() as *const T)).clone())
        }
    }

    fn read_block(&self, id: Oid, offset: usize, buf: &mut [u8]) -> KResult<()> {
        if offset + buf.len() > BLOCK_SIZE {
            error!("offset + buf.len() exceeds the block size (4KB).");
            return Err(Errno::EINVAL);
        }

        match self.read_buf_at(offset + id as usize * BLOCK_SIZE, buf) {
            Ok(len) => {
                if len == buf.len() {
                    Ok(())
                } else {
                    Err(Errno::EINVAL)
                }
            }
            Err(errno) => {
                error!("failed to read buffer. Errno: {:?}", errno);
                Err(errno)
            }
        }
    }

    fn write_block(&self, id: Oid, offset: usize, buf: &[u8]) -> KResult<()> {
        if offset + buf.len() > BLOCK_SIZE {
            error!("offset + buf.len() exceeds the block size (4KB).");
            return Err(Errno::EINVAL);
        }

        match self.write_buf_at(offset + id as usize * BLOCK_SIZE, buf) {
            Ok(len) => {
                if len == buf.len() {
                    Ok(())
                } else {
                    Err(Errno::EINVAL)
                }
            }
            Err(errno) => {
                error!("failed to write buffer. Errno: {:?}", errno);
                Err(errno)
            }
        }
    }
}

impl BlockLike for dyn Device {}

/// Represents the instance of the APFS.
///
/// The inode is a unique identifier that identifies a file system object — a file or a folder
pub struct AppleFileSystem {
    // TODO: What should be included here?
    superblock: MaybeDirty<RwLock<NxSuperBlock>>,
    device: Arc<dyn Device>,
    volumn_lists: RwLock<Vec<ApfsSuperblock>>,
    omap_root: RwLock<Option<(BTreeNodePhysical, BTreeInfo)>>,
    omap: RwLock<Option<ObjectMap>>,
}

impl AppleFileSystem {
    /// Mounts the filesystem via a device driver (AHCI SATA) and returns a arc-ed instance. We only need the superblock.
    pub fn mount(device: Arc<dyn Device>) -> KResult<Arc<Self>> {
        // Step 1: Read block zero of the partition. This block contains a copy of the container superblock
        // (an instance of `nx_superblock_t`). It might be a copy of the latest version or an old version,
        // depending on whether the drive was unmounted cleanly.
        let mut nx_superblock = device.load_struct::<NxSuperBlock>(0)?;

        // Verify the block.
        if !nx_superblock.verify() {
            return Err(Errno::EINVAL);
        }

        // Step 2: Use the block-zero copy of the container superblock to locate the checkpoint descriptor area
        // by reading the `nx_xp_desc_base` field.
        let nx_xp_desc_base = nx_superblock.nx_xp_desc_base;
        let highest_bit = nx_xp_desc_base & (1 << 63);
        if highest_bit != 0 {
            error!("currently we do not support non-contiguous checkpoint descriptor area");
            return Err(Errno::EACCES);
        }

        // Step 3: Read the entries in the checkpoint descriptor area, which are instances of `checkpoint_map_phys_t`.
        // or `nx_superblock_t`.
        let mut best_xid = 0;
        for idx in 0..nx_superblock.nx_xp_desc_blocks {
            info!("reading {idx}...");
            // Should check whether this object is a checkpoint mapping or another superblock.
            // This can be done by reading the header of the target block.
            let addr = nx_xp_desc_base + idx as u64;
            let object = match read_object(&device, addr) {
                Ok(object) => object,
                Err(_) => continue,
            };

            // Check the type.
            let hdr = unsafe { &*(object.as_ptr() as *const ObjectPhysical) };
            let object_type = ObjectTypes::from_bits_truncate((hdr.o_type & 0xff) as _);
            match object_type {
                // Find the container superblock that has the largest transaction identifier and isnʼt malformed.
                ObjectTypes::OBJECT_TYPE_NX_SUPERBLOCK => {
                    let cur_superblock = unsafe { &*(object.as_ptr() as *const NxSuperBlock) };
                    // The checkpoint description area is a ring buffer stored as an array. So performing a modulo is
                    // necessary at this timepoint.
                    let map_addr = cur_superblock.nx_xp_desc_base
                        + ((idx + cur_superblock.nx_xp_desc_blocks - 1)
                            % cur_superblock.nx_xp_desc_blocks) as u64;
                    let map_object = unsafe {
                        let map_object = read_object(&device, map_addr)?;
                        &*(map_object.as_ptr() as *const CheckpointMapPhysical)
                    };

                    // Find the latest superblock.
                    if map_object.cpm_o.o_xid > best_xid {
                        best_xid = map_object.cpm_o.o_xid;
                        nx_superblock = cur_superblock.clone();
                    }
                }
                _ => continue,
            }
        }

        info!("mounted the superblock: {:x?}", nx_superblock);
        Ok(Arc::new(Self {
            superblock: MaybeDirty::new(RwLock::new(nx_superblock)),
            device: device.clone(),
            volumn_lists: RwLock::new(Vec::new()),
            omap_root: RwLock::new(None),
            omap: RwLock::new(None),
        }))
    }

    pub fn load_object_map(&self) -> KResult<()> {
        let omap_phys_oid = self.superblock.read().nx_omap_oid;
        let buf = read_object(&self.device, omap_phys_oid)?;
        let omap_phys = unsafe { &*(buf.as_ptr() as *const ObjectMapPhysical) };

        // Check if the OMAP physical descriptor is correct.

        // Read the root node.
        let root_node_oid = omap_phys.om_tree_oid;
        let buf = read_object(&self.device, root_node_oid)?;
        let root_node = unsafe { &*(buf.as_ptr() as *const BTreeNodePhysical) };

        // Check if root node is correct.
        let btree_node_flags = BTreeNodeFlags::from_bits_truncate(root_node.btn_flags);
        if !btree_node_flags.contains(BTreeNodeFlags::BTNODE_ROOT) {
            log::error!("trying to parse a non-root node; abort.");
            return Err(Errno::EINVAL);
        } else if !btree_node_flags.contains(BTreeNodeFlags::BTNODE_FIXED_KV_SIZE) {
            log::error!("non-fixed k-v pairs are not supported; abort.");
            return Err(Errno::EINVAL);
        }

        // If this is the root node, then the end of the block contains the B-Tree node information, and we
        // should parse this information so that we know how the tree is organized.
        let btree_info = root_node
            .btn_data
            .iter()
            .copied()
            .rev()
            .take(core::mem::size_of::<BTreeInfo>())
            .rev() // Note the endianess.
            .collect::<Vec<_>>();

        // Parse the information.
        let btree_info = unsafe { &*(btree_info.as_ptr() as *const BTreeInfo) };
        log::info!("loaded BTree information: {:#x?}", btree_info);
        let omap = root_node.parse_as_object_map()?;

        self.omap_root
            .write()
            .replace((root_node.clone(), btree_info.clone()));
        self.omap.write().replace(omap);

        Ok(())
    }

    /// Mounts all volumns
    pub fn mount_volumns_all(&self) -> KResult<()> {
        // Read from the nx_fs_oid.
        let nx_fs_oid = self.superblock.read().nx_fs_oid;

        // For each volume, look up the specified virtual object identifier in the container object map to locate the
        // volume superblock. Since oid must not be zero, we can skip zeros.
        let valid_fs_oids = nx_fs_oid
            .into_iter()
            .filter(|&oid| oid != 0)
            .collect::<Vec<_>>();

        info!("map = {:x?}", self.omap);

        for oid in valid_fs_oids {
            let key = ObjectMapKey {
                ok_oid: oid,
                // TODO: There is no transaction id currently.
                ok_xid: 0x1,
            };

            log::info!("mounting {:x?}", key);
            self.mount_volumn(&key)?;
        }

        Ok(())
    }

    /// Mounts other volumn.
    pub fn mount_volumn(&self, omap_key: &ObjectMapKey) -> KResult<()> {
        let omap = self.omap.read();
        let omap_root = self.omap_root.read();

        if omap.is_none() || omap_root.is_none() {
            log::error!("cannot mount other volumns if we have not mounted the container!");
            return Err(Errno::ENODEV);
        }

        let entry = match omap.as_ref().unwrap().get(omap_key) {
            Some(entry) => entry,
            None => {
                log::error!("the requested volumn does not exist.");
                return Err(Errno::ENOENT);
            }
        };
        if entry.ov_size as usize % BLOCK_SIZE != 0 {
            log::error!("not aligned to block size.");
            return Err(Errno::EINVAL);
        }

        let object = read_object(&self.device, entry.ov_paddr)?;
        // Parse it as apfs_superblock_t.
        let apfs_superblock = unsafe { &*(object.as_ptr() as *const ApfsSuperblock) }.clone();
        info!("apfs_superblock = {:x?}", apfs_superblock);

        let volumn_name =
            String::from_utf8(apfs_superblock.apfs_volname.to_vec()).map_err(|_| Errno::EINVAL)?;
        log::info!("successfully mounted volumn: {volumn_name}.");

        self.volumn_lists.write().push(apfs_superblock);

        Ok(())
    }

    pub fn read_apfs_trees(&self) -> KResult<()> {
        for superblock in self.volumn_lists.read().iter() {
            let buf = read_object(&self.device, superblock.apfs_omap_oid)?;
            let omap_phys = unsafe { &*(buf.as_ptr() as *const ObjectMapPhysical) };

            // Check if the OMAP physical descriptor is correct.

            // Read the root node.
            let root_node_oid = omap_phys.om_tree_oid;
            let buf = read_object(&self.device, root_node_oid)?;
            let root_node = unsafe { &*(buf.as_ptr() as *const BTreeNodePhysical) };

            // Check if root node is correct.
            let btree_node_flags = BTreeNodeFlags::from_bits_truncate(root_node.btn_flags);
            if !btree_node_flags.contains(BTreeNodeFlags::BTNODE_ROOT) {
                log::error!("trying to parse a non-root node; abort.");
                return Err(Errno::EINVAL);
            } else if !btree_node_flags.contains(BTreeNodeFlags::BTNODE_FIXED_KV_SIZE) {
                log::error!("non-fixed k-v pairs are not supported; abort.");
                return Err(Errno::EINVAL);
            }

            // If this is the root node, then the end of the block contains the B-Tree node information, and we
            // should parse this information so that we know how the tree is organized.
            let btree_info = root_node
                .btn_data
                .iter()
                .copied()
                .rev()
                .take(core::mem::size_of::<BTreeInfo>())
                .rev() // Note the endianess.
                .collect::<Vec<_>>();

            // Parse the information.
            let btree_info = unsafe { &*(btree_info.as_ptr() as *const BTreeInfo) };
            log::info!("loaded BTree information: {:#x?}", btree_info);
            let omap = root_node.parse_as_object_map()?;

            log::info!("it is {:x?}", omap);
        }

        Ok(())
    }

    pub fn get_map_oid(&self) -> Oid {
        self.superblock.read().nx_omap_oid
    }
}

pub struct AppleFileSystemInode {
    // TODO: What should be included here?
    fs: Arc<AppleFileSystem>,
}

impl FileSystem for AppleFileSystem {
    fn sync(&self) -> rcore_fs::vfs::Result<()> {
        todo!()
    }

    fn root_inode(&self) -> Arc<dyn INode> {
        todo!()
    }

    fn info(&self) -> rcore_fs::vfs::FsInfo {
        todo!()
    }
}

impl INode for AppleFileSystemInode {
    fn read_at(&self, offset: usize, buf: &mut [u8]) -> rcore_fs::vfs::Result<usize> {
        todo!()
    }

    fn write_at(&self, offset: usize, buf: &[u8]) -> rcore_fs::vfs::Result<usize> {
        todo!()
    }

    fn poll(&self) -> rcore_fs::vfs::Result<rcore_fs::vfs::PollStatus> {
        todo!()
    }

    fn as_any_ref(&self) -> &dyn core::any::Any {
        todo!()
    }
}

/// Reads a file object from the disk at a given address.
fn read_object(device: &Arc<dyn Device>, addr: u64) -> KResult<Vec<u8>> {
    let mut buf = vec![0u8; BLOCK_SIZE];
    device.read_block(addr, 0, &mut buf)?;

    let hdr = unsafe { &*(buf.as_ptr() as *const ObjectPhysical) };
    let cs = calc_fletcher64(&buf[8..])?;
    if cs != hdr.o_cksum {
        error!("corrupted/invalid block: cs = {}, o_cksum = {}", cs, hdr.o_cksum);
        Err(Errno::EINVAL)
    } else {
        Ok(buf)
    }
}

impl Device for Vec<u8> {
    fn read_buf_at(&self, offset: usize, buf: &mut [u8]) -> KResult<usize> {
        buf.copy_from_slice(&self[offset..offset + buf.len()]);
        Ok(buf.len())
    }

    fn sync(&self) -> KResult<()> {
        Ok(())
    }

    fn write_buf_at(&self, _offset: usize, _buf: &[u8]) -> KResult<usize> {
        Ok(0)
    }
}
