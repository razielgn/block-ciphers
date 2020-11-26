//! Autodetection support for hardware accelerated AES backends with fallback
//! to the fixsliced "soft" implementation.

use crate::{Block, ParBlocks};
use cipher::{
    consts::{U16, U24, U32, U8},
    generic_array::GenericArray,
    BlockCipher, BlockDecrypt, BlockEncrypt, NewBlockCipher,
};

macro_rules! define_aes_impl {
    (
        $name:tt,
        $module:tt,
        $key_size:ty,
        $doc:expr
    ) => {
        #[doc=$doc]
        #[derive(Clone)]
        pub struct $name($module::Inner);

        mod $module {
            #[derive(Clone)]
            pub(super) enum Inner {
                Ni(crate::ni::$name),
                Soft(crate::soft::$name),
            }
        }

        impl NewBlockCipher for $name {
            type KeySize = $key_size;

            #[inline]
            fn new(key: &GenericArray<u8, $key_size>) -> Self {
                if cpuid_bool::cpuid_bool!("aes") {
                    $name($module::Inner::Ni(crate::ni::$name::new(key)))
                } else {
                    $name($module::Inner::Soft(crate::soft::$name::new(key)))
                }
            }
        }

        impl BlockCipher for $name {
            type BlockSize = U16;
            type ParBlocks = U8;
        }

        impl BlockEncrypt for $name {
            #[inline]
            fn encrypt_block(&self, block: &mut Block) {
                match &self.0 {
                    $module::Inner::Ni(aes) => aes.encrypt_block(block),
                    $module::Inner::Soft(aes) => aes.encrypt_block(block),
                }
            }

            #[inline]
            fn encrypt_par_blocks(&self, blocks: &mut ParBlocks) {
                match &self.0 {
                    $module::Inner::Ni(aes) => aes.encrypt_par_blocks(blocks),
                    $module::Inner::Soft(aes) => aes.encrypt_par_blocks(blocks),
                }
            }
        }

        impl BlockDecrypt for $name {
            #[inline]
            fn decrypt_block(&self, block: &mut Block) {
                match &self.0 {
                    $module::Inner::Ni(aes) => aes.decrypt_block(block),
                    $module::Inner::Soft(aes) => aes.decrypt_block(block),
                }
            }

            #[inline]
            fn decrypt_par_blocks(&self, blocks: &mut ParBlocks) {
                match &self.0 {
                    $module::Inner::Ni(aes) => aes.decrypt_par_blocks(blocks),
                    $module::Inner::Soft(aes) => aes.decrypt_par_blocks(blocks),
                }
            }
        }

        opaque_debug::implement!($name);
    }
}

define_aes_impl!(
    Aes128,
    aes128,
    U16,
    "AES-128 block cipher instance"
);

define_aes_impl!(
    Aes192,
    aes192,
    U24,
    "AES-192 block cipher instance"
);

define_aes_impl!(
    Aes256,
    aes256,
    U32,
    "AES-256 block cipher instance"
);
