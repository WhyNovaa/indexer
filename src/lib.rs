use std::{
    cmp::Ordering,
    collections::BTreeMap,
    fs,
    io::{Cursor, Read},
    marker::PhantomData,
    ops::ControlFlow,
    path::PathBuf,
    thread,
};

use blk_index_to_blk_path::*;
use blk_recap::BlkRecap;
use crossbeam::channel::{Receiver, bounded};
use rayon::prelude::*;

mod blk_index_to_blk_path;
mod blk_index_to_blk_recap;
mod blk_metadata;
mod blk_recap;
mod block_state;
mod error;
mod utils;

pub use bitcoin_hashes::sha256d;
use blk_index_to_blk_recap::*;
use blk_metadata::*;
use block_state::*;
pub use error::*;
use utils::*;

pub trait InnerBlockHash: Sized + Send + Sync {
    type Error: std::fmt::Debug;

    fn inner_block_hash(&self) -> sha256d::Hash;
    fn consensus_decode<C: std::io::Read + ?Sized>(cursor: &mut C) -> Result<Self, Self::Error>;
}

#[cfg(feature = "bellscoin")]
impl InnerBlockHash for bellscoin::Block {
    type Error = bellscoin::consensus::encode::Error;

    fn inner_block_hash(&self) -> sha256d::Hash {
        let bytes = *bellscoin::hashes::Hash::as_byte_array(self.block_hash().as_raw_hash());
        sha256d::Hash::from_byte_array(bytes)
    }

    fn consensus_decode<C: std::io::Read + ?Sized>(cursor: &mut C) -> Result<Self, Self::Error> {
        bellscoin::consensus::Decodable::consensus_decode(cursor)
    }
}

#[cfg(feature = "dogecoin")]
impl InnerBlockHash for nintondo_dogecoin::Block {
    type Error = nintondo_dogecoin::consensus::encode::Error;

    fn inner_block_hash(&self) -> sha256d::Hash {
        let bytes =
            *nintondo_dogecoin::hashes::Hash::as_byte_array(self.block_hash().as_raw_hash());
        sha256d::Hash::from_byte_array(bytes)
    }

    fn consensus_decode<C: std::io::Read + ?Sized>(cursor: &mut C) -> Result<Self, Self::Error> {
        nintondo_dogecoin::consensus::Decodable::consensus_decode(cursor)
    }
}

pub(crate) type Height = u32;
pub(crate) type Confirmations = i32;

pub trait NodeClient: Send + Sync {
    type Error: std::fmt::Debug;

    fn get_block_header_info(
        &self,
        hash: &sha256d::Hash,
    ) -> Result<(Height, Confirmations), Self::Error>;
}

#[cfg(feature = "bellscoin")]
impl NodeClient for bellscoincore_rpc::Client {
    type Error = bellscoincore_rpc::Error;

    fn get_block_header_info(
        &self,
        hash: &sha256d::Hash,
    ) -> Result<(Height, Confirmations), Self::Error> {
        let hash = <bellscoin::BlockHash as bellscoin::hashes::Hash>::from_byte_array(
            hash.to_byte_array(),
        );

        bellscoincore_rpc::RpcApi::get_block_header_info(self, &hash)
            .map(|x| (x.height as u32, x.confirmations))
    }
}

const BOUND_CAP: usize = 50;

pub struct Parser<T: InnerBlockHash, U: NodeClient + 'static> {
    blocks_dir: PathBuf,
    rpc: &'static U,
    magic: [u8; 4],
    _block: PhantomData<T>,
}

impl<T: InnerBlockHash + 'static, U: NodeClient + 'static> Parser<T, U> {
    pub fn new(blocks_dir: PathBuf, rpc: &'static U, magic: [u8; 4]) -> Self {
        Self {
            blocks_dir,
            rpc,
            magic,
            _block: PhantomData,
        }
    }

    pub fn get(&self, height: Height) -> T {
        self.parse(Some(height), Some(height))
            .iter()
            .next()
            .unwrap()
            .1
    }

    /// Returns a crossbeam channel receiver that receives `(Height, Block, BlockHash)` tuples from an **inclusive** range (`start` and `end`)
    pub fn parse(
        &self,
        start: Option<Height>,
        end: Option<Height>,
    ) -> Receiver<(Height, T, bitcoin_hashes::sha256d::Hash)> {
        let blocks_dir = self.blocks_dir.as_path();
        let rpc = self.rpc;

        let (send_bytes, recv_bytes) = bounded(BOUND_CAP);
        let (send_block, recv_block) = bounded(BOUND_CAP);
        let (send_height_block_hash, recv_height_block_hash) = bounded(BOUND_CAP);

        let blk_index_to_blk_path = BlkIndexToBlkPath::scan(blocks_dir);

        let (mut blk_index_to_blk_recap, blk_index) =
            BlkIndexToBlkRecap::import(blocks_dir, &blk_index_to_blk_path, start);

        let magic = self.magic;

        thread::spawn(move || {
            blk_index_to_blk_path
                .range(blk_index..)
                .try_for_each(move |(blk_index, blk_path)| {
                    let blk_index = *blk_index;

                    let blk_metadata = BlkMetadata::new(blk_index, blk_path.as_path());

                    let mut blk_bytes_ = fs::read(blk_path).unwrap();
                    let blk_bytes = blk_bytes_.as_mut_slice();
                    let blk_bytes_len = blk_bytes.len();

                    let mut current_4bytes = [0; 4];
                    let mut cursor = Cursor::new(blk_bytes);

                    while cursor.position() < blk_bytes_len as u64 {
                        cursor.read_exact(&mut current_4bytes).unwrap();

                        if current_4bytes != magic {
                            break;
                        }

                        let mut len_bytes = [0u8; 4];
                        cursor
                            .read_exact(&mut len_bytes)
                            .expect("Invalid length of block");
                        let len = u32::from_le_bytes(len_bytes);

                        let mut block_result = vec![0; len as usize];
                        cursor
                            .read_exact(&mut block_result)
                            .expect("Failed to read block bytes");

                        if send_bytes
                            .send((blk_metadata, BlockState::<T>::Raw(block_result)))
                            .is_err()
                        {
                            return ControlFlow::Break(());
                        }
                    }

                    ControlFlow::Continue(())
                });
        });

        thread::spawn(move || {
            let mut bulk = vec![];

            let drain_and_send = |bulk: &mut Vec<_>| {
                // Using a vec and sending after to not end up with stuck threads in par iter
                bulk.par_iter_mut().for_each(|(_, block_state)| {
                    BlockState::decode(block_state);
                });

                bulk.drain(..).try_for_each(|(blk_metadata, block_state)| {
                    let block = match block_state {
                        BlockState::Decoded(block) => block,
                        _ => unreachable!(),
                    };

                    if send_block.send((blk_metadata, block)).is_err() {
                        return ControlFlow::Break(());
                    }

                    ControlFlow::Continue(())
                })
            };

            recv_bytes.iter().try_for_each(|tuple| {
                bulk.push(tuple);

                if bulk.len() < BOUND_CAP / 2 {
                    return ControlFlow::Continue(());
                }

                // Sending in bulk to not lock threads in standby
                drain_and_send(&mut bulk)
            });

            drain_and_send(&mut bulk)
        });

        thread::spawn(move || {
            let mut current_height = start.unwrap_or_default();

            let mut future_blocks = BTreeMap::default();

            recv_block
                .iter()
                .try_for_each(|(blk_metadata, block)| -> ControlFlow<(), _> {
                    let hash = block.inner_block_hash();
                    let header = rpc.get_block_header_info(&hash);

                    if header.is_err() {
                        return ControlFlow::Continue(());
                    }
                    let (height, confirmations) = header.unwrap();
                    if confirmations <= 0 {
                        return ControlFlow::Continue(());
                    }

                    let len = blk_index_to_blk_recap.tree.len();
                    if blk_metadata.index == len as u16 || blk_metadata.index + 1 == len as u16 {
                        match (len as u16).cmp(&blk_metadata.index) {
                            Ordering::Equal => {
                                if len % 21 == 0 {
                                    blk_index_to_blk_recap.export();
                                }
                            }
                            Ordering::Less => panic!(),
                            Ordering::Greater => {}
                        }

                        blk_index_to_blk_recap
                            .tree
                            .entry(blk_metadata.index)
                            .and_modify(|recap| {
                                if recap.max_height < height {
                                    recap.max_height = height;
                                }
                            })
                            .or_insert(BlkRecap {
                                max_height: height,
                                modified_time: blk_metadata.modified_time,
                            });
                    }

                    let mut opt = if current_height == height {
                        Some((block, hash))
                    } else {
                        if start.is_none_or(|start| start <= height)
                            && end.is_none_or(|end| end >= height)
                        {
                            future_blocks.insert(height, (block, hash));
                        }
                        None
                    };

                    while let Some((block, hash)) = opt.take().or_else(|| {
                        if !future_blocks.is_empty() {
                            future_blocks.remove(&current_height)
                        } else {
                            None
                        }
                    }) {
                        if end.is_some_and(|end| end < current_height) {
                            return ControlFlow::Break(());
                        }

                        send_height_block_hash
                            .send((current_height, block, hash))
                            .unwrap();

                        if end.is_some_and(|end| end == current_height) {
                            return ControlFlow::Break(());
                        }

                        current_height += 1;
                    }

                    ControlFlow::Continue(())
                });

            blk_index_to_blk_recap.export();
        });

        recv_height_block_hash
    }
}
