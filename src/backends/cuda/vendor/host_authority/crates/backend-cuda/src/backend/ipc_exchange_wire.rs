use super::{rounded_allocation_bytes, IpcExchangeError};

pub const CUDA_DEVICE_UUID_BYTES: usize = 16;
pub const CUDA_IPC_HANDLE_BYTES: usize = 64;
pub const IPC_EXCHANGE_INSTALL_DOMAIN_BYTES: usize = 32;
pub const IPC_EXCHANGE_DESCRIPTOR_BYTES: usize = 312;
pub const IPC_EXCHANGE_CLOSE_RECEIPT_BYTES: usize = 120;

const DESCRIPTOR_MAGIC: [u8; 8] = *b"STWOIPCX";
const CLOSE_MAGIC: [u8; 8] = *b"STWOIPCC";
const VERSION: u32 = 2;
const OWNER_TO_PEER_DIRECTION: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CudaDeviceUuid([u8; CUDA_DEVICE_UUID_BYTES]);

impl CudaDeviceUuid {
    pub(crate) const fn from_bytes(bytes: [u8; CUDA_DEVICE_UUID_BYTES]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; CUDA_DEVICE_UUID_BYTES] {
        &self.0
    }
}

/// Controller installation domain shared by every edge in one fleet install.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IpcExchangeInstallDomain([u8; IPC_EXCHANGE_INSTALL_DOMAIN_BYTES]);

impl IpcExchangeInstallDomain {
    pub fn from_digest(
        digest: [u8; IPC_EXCHANGE_INSTALL_DOMAIN_BYTES],
    ) -> Result<Self, IpcExchangeError> {
        if digest == [0; IPC_EXCHANGE_INSTALL_DOMAIN_BYTES] {
            return Err(IpcExchangeError::InvalidKey("zero install domain"));
        }
        Ok(Self(digest))
    }

    pub const fn as_bytes(&self) -> &[u8; IPC_EXCHANGE_INSTALL_DOMAIN_BYTES] {
        &self.0
    }
}

/// Static identity of one directed owner-to-peer exchange edge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IpcExchangeKey {
    pub(super) edge_id: u64,
    pub(super) owner_rank: u32,
    pub(super) peer_rank: u32,
    pub(super) owner_device: CudaDeviceUuid,
    pub(super) peer_device: CudaDeviceUuid,
    pub(super) install_domain: IpcExchangeInstallDomain,
    pub(super) logical_bytes: usize,
    pub(super) initial_generation: u64,
}

impl IpcExchangeKey {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        edge_id: u64,
        owner_rank: u32,
        peer_rank: u32,
        owner_device: CudaDeviceUuid,
        peer_device: CudaDeviceUuid,
        install_domain: IpcExchangeInstallDomain,
        logical_bytes: usize,
        initial_generation: u64,
    ) -> Result<Self, IpcExchangeError> {
        if owner_rank == peer_rank {
            return Err(IpcExchangeError::InvalidKey(
                "owner and peer ranks are equal",
            ));
        }
        if initial_generation == u64::MAX {
            return Err(IpcExchangeError::InvalidKey(
                "initial generation cannot advance",
            ));
        }
        if owner_device.0 == [0; CUDA_DEVICE_UUID_BYTES]
            || peer_device.0 == [0; CUDA_DEVICE_UUID_BYTES]
            || owner_device == peer_device
        {
            return Err(IpcExchangeError::InvalidKey(
                "device UUIDs are not distinct",
            ));
        }
        let allocation_bytes = rounded_allocation_bytes(logical_bytes)?;
        u64::try_from(logical_bytes)
            .map_err(|_| IpcExchangeError::InvalidKey("logical extent exceeds u64"))?;
        u64::try_from(allocation_bytes)
            .map_err(|_| IpcExchangeError::InvalidKey("allocation extent exceeds u64"))?;
        Ok(Self {
            edge_id,
            owner_rank,
            peer_rank,
            owner_device,
            peer_device,
            install_domain,
            logical_bytes,
            initial_generation,
        })
    }

    pub const fn edge_id(self) -> u64 {
        self.edge_id
    }

    pub const fn owner_rank(self) -> u32 {
        self.owner_rank
    }

    pub const fn peer_rank(self) -> u32 {
        self.peer_rank
    }

    pub const fn owner_device(self) -> CudaDeviceUuid {
        self.owner_device
    }

    pub const fn peer_device(self) -> CudaDeviceUuid {
        self.peer_device
    }

    pub const fn install_domain(self) -> IpcExchangeInstallDomain {
        self.install_domain
    }

    pub const fn logical_bytes(self) -> usize {
        self.logical_bytes
    }

    pub const fn initial_generation(self) -> u64 {
        self.initial_generation
    }
}

/// Process-portable classic CUDA IPC memory and two-event handshake handles.
#[must_use = "the importing rank needs this descriptor before publication"]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IpcExchangeDescriptor {
    pub(super) key: IpcExchangeKey,
    pub(super) allocation_bytes: usize,
    pub(super) memory_handle: [u8; CUDA_IPC_HANDLE_BYTES],
    pub(super) ready_event_handle: [u8; CUDA_IPC_HANDLE_BYTES],
    pub(super) consumed_event_handle: [u8; CUDA_IPC_HANDLE_BYTES],
}

impl IpcExchangeDescriptor {
    pub const fn key(&self) -> IpcExchangeKey {
        self.key
    }

    pub const fn allocation_bytes(&self) -> usize {
        self.allocation_bytes
    }

    /// Canonical little-endian wire image for the authenticated coordinator.
    pub fn encode(&self) -> [u8; IPC_EXCHANGE_DESCRIPTOR_BYTES] {
        let mut out = [0u8; IPC_EXCHANGE_DESCRIPTOR_BYTES];
        encode_key(
            &mut out[..120],
            DESCRIPTOR_MAGIC,
            self.key,
            self.key.initial_generation,
        );
        out[48..56].copy_from_slice(&(self.allocation_bytes as u64).to_le_bytes());
        out[120..184].copy_from_slice(&self.memory_handle);
        out[184..248].copy_from_slice(&self.ready_event_handle);
        out[248..312].copy_from_slice(&self.consumed_event_handle);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, IpcExchangeError> {
        if bytes.len() != IPC_EXCHANGE_DESCRIPTOR_BYTES {
            return Err(IpcExchangeError::InvalidDescriptor("descriptor size"));
        }
        let key = decode_key(&bytes[..120], DESCRIPTOR_MAGIC, false)?.0;
        let allocation_bytes = usize::try_from(read_u64(bytes, 48))
            .map_err(|_| IpcExchangeError::InvalidDescriptor("allocation byte extent"))?;
        if allocation_bytes != rounded_allocation_bytes(key.logical_bytes)? {
            return Err(IpcExchangeError::InvalidDescriptor("allocation geometry"));
        }
        let mut memory_handle = [0u8; CUDA_IPC_HANDLE_BYTES];
        memory_handle.copy_from_slice(&bytes[120..184]);
        let mut ready_event_handle = [0u8; CUDA_IPC_HANDLE_BYTES];
        ready_event_handle.copy_from_slice(&bytes[184..248]);
        let mut consumed_event_handle = [0u8; CUDA_IPC_HANDLE_BYTES];
        consumed_event_handle.copy_from_slice(&bytes[248..312]);
        Ok(Self {
            key,
            allocation_bytes,
            memory_handle,
            ready_event_handle,
            consumed_event_handle,
        })
    }
}

#[must_use = "the owner must receive this receipt before freeing the export"]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IpcPeerCloseReceipt {
    pub(super) key: IpcExchangeKey,
    pub(super) generation: u64,
}

impl IpcPeerCloseReceipt {
    pub const fn key(&self) -> IpcExchangeKey {
        self.key
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub fn encode(&self) -> [u8; IPC_EXCHANGE_CLOSE_RECEIPT_BYTES] {
        let mut out = [0u8; IPC_EXCHANGE_CLOSE_RECEIPT_BYTES];
        encode_key(&mut out, CLOSE_MAGIC, self.key, self.generation);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, IpcExchangeError> {
        let (key, generation) = decode_key(bytes, CLOSE_MAGIC, true)?;
        if generation < key.initial_generation {
            return Err(IpcExchangeError::InvalidDescriptor(
                "close generation predates descriptor",
            ));
        }
        Ok(Self { key, generation })
    }
}

fn encode_key(out: &mut [u8], magic: [u8; 8], key: IpcExchangeKey, generation: u64) {
    out[0..8].copy_from_slice(&magic);
    out[8..12].copy_from_slice(&VERSION.to_le_bytes());
    out[12..16].copy_from_slice(&OWNER_TO_PEER_DIRECTION.to_le_bytes());
    out[16..24].copy_from_slice(&key.edge_id.to_le_bytes());
    out[24..28].copy_from_slice(&key.owner_rank.to_le_bytes());
    out[28..32].copy_from_slice(&key.peer_rank.to_le_bytes());
    out[32..40].copy_from_slice(&key.initial_generation.to_le_bytes());
    out[40..48].copy_from_slice(&(key.logical_bytes as u64).to_le_bytes());
    out[56..72].copy_from_slice(key.owner_device.as_bytes());
    out[72..88].copy_from_slice(key.peer_device.as_bytes());
    out[88..120].copy_from_slice(key.install_domain.as_bytes());
    if magic == CLOSE_MAGIC {
        out[48..56].copy_from_slice(&generation.to_le_bytes());
    }
}

fn decode_key(
    bytes: &[u8],
    magic: [u8; 8],
    close: bool,
) -> Result<(IpcExchangeKey, u64), IpcExchangeError> {
    if bytes.len() != IPC_EXCHANGE_CLOSE_RECEIPT_BYTES || bytes[0..8] != magic {
        return Err(IpcExchangeError::InvalidDescriptor("size or magic"));
    }
    if read_u32(bytes, 8) != VERSION || read_u32(bytes, 12) != OWNER_TO_PEER_DIRECTION {
        return Err(IpcExchangeError::InvalidDescriptor("version or direction"));
    }
    let logical_bytes = usize::try_from(read_u64(bytes, 40))
        .map_err(|_| IpcExchangeError::InvalidDescriptor("logical byte extent"))?;
    let mut owner_uuid = [0u8; CUDA_DEVICE_UUID_BYTES];
    owner_uuid.copy_from_slice(&bytes[56..72]);
    let mut peer_uuid = [0u8; CUDA_DEVICE_UUID_BYTES];
    peer_uuid.copy_from_slice(&bytes[72..88]);
    let mut install_domain = [0u8; IPC_EXCHANGE_INSTALL_DOMAIN_BYTES];
    install_domain.copy_from_slice(&bytes[88..120]);
    let key = IpcExchangeKey::new(
        read_u64(bytes, 16),
        read_u32(bytes, 24),
        read_u32(bytes, 28),
        CudaDeviceUuid(owner_uuid),
        CudaDeviceUuid(peer_uuid),
        IpcExchangeInstallDomain::from_digest(install_domain)?,
        logical_bytes,
        read_u64(bytes, 32),
    )?;
    Ok((
        key,
        close
            .then(|| read_u64(bytes, 48))
            .unwrap_or(key.initial_generation),
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
