//! this contract is not audited

#![cfg_attr(not(any(feature = "export-abi", test)), no_main)]
extern crate alloc;

use alloc::vec::Vec;
use alloy_primitives::{b256, U64};
use alloy_sol_types::sol;
use stylus_sdk::{
    alloy_primitives::{Address, B256, U256}, call::RawCall, crypto, prelude::*
};

// Compact error handling
#[derive(SolidityError)]
pub enum AirdropErrors {
    AirdropError(AirdropError),
}

// Error codes for compact error handling
pub const ERROR_LENGTH_MISMATCH: u8 = 1;
pub const ERROR_NO_MERKLE_ROOT: u8 = 2;
pub const ERROR_INVALID_PROOF: u8 = 3;
pub const ERROR_ALREADY_CLAIMED: u8 = 4;
pub const ERROR_REQUEST_EXPIRED: u8 = 5;
pub const ERROR_UID_ALREADY_USED: u8 = 6;
pub const ERROR_INVALID_SIGNATURE: u8 = 7;
pub const ERROR_NOT_OWNER: u8 = 8;

sol_interface! {
    interface IERC1155 {
        function safeTransferFrom(address _from, address _to, uint256 _id, uint256 _value, bytes calldata _data) external;
    }
}

sol! {

    struct AirdropContentERC1155 {
        address recipient;
        uint256 tokenId;
        uint256 amount;
    }

    struct AirdropRequestERC1155 {
        bytes32 uid;
        address tokenAddress;
        uint256 expirationTimestamp;
        AirdropContentERC1155[] contents;
    }

    // Compact error codes
    error AirdropError(uint8 code);
}

sol_storage! {
    #[entrypoint]
    pub struct StylusAirdropERC1155 {
        address owner;

        mapping(address => uint64) tokenConditionId;
        mapping(address => bytes32) tokenMerkleRoot;
        mapping(bytes32 => bool) claimed; 

        mapping(bytes32  => bool) processed; 
    }
}

// keccak256("AirdropContentERC1155(address recipient,uint256 tokenId,uint256 amount)")
const CONTENT_TYPEHASH_ERC1155:  B256 =
b256!("994ce640e86e890d563f649cc713a08cc6ad71bf546608888242f1265b2917f9");

// keccak256("AirdropRequestERC1155(bytes32 uid,address tokenAddress,uint256 expirationTimestamp,AirdropContentERC1155[] contents)AirdropContentERC1155(address recipient,uint256 tokenId,uint256 amount)")
const REQUEST_TYPEHASH_ERC1155:  B256 =
 b256!("2eab25a5d073c19ac26a4e09b16736d071d8db876220e1e5b2dea3b02a4d9421");

const EIP712_DOMAIN_TYPEHASH: B256 =
 b256!("8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f");

#[public]
impl StylusAirdropERC1155 {
    #[constructor]
    pub fn constructor(&mut self, owner: Address) {
        let _ = self.owner.set(owner);
    }

    #[selector(name = "airdropERC1155")]
    pub fn airdrop_erc1155(
        &mut self,
        token:      Address,
        contents: Vec<(Address, U256, U256)>,
    ) -> Result<(), AirdropErrors> {

        let erc1155 = IERC1155::from(token);
        let sender = self.vm().msg_sender();

        for (recipient, token_id, amount) in &contents {
            let config = Call::new_mutating(self);
            erc1155
                .safe_transfer_from(self.vm(), config, sender, *recipient, *token_id, *amount, "".into())
                .expect("fail");
        }

        // TODO: emit log
        Ok(())
    }

    #[payable]
    #[selector(name = "claimERC1155")]
    pub fn claim_erc1155(
        &mut self,
        token:   Address,
        receiver: Address,
        token_id:  U256,
        amount:  U256,
        proofs:  Vec<B256>,
    ) -> Result<(), AirdropErrors> {

        // 1. root must exist
        let root = self.tokenMerkleRoot.get(token);
        if root == B256::ZERO {
            return Err(AirdropErrors::AirdropError(AirdropError { code: ERROR_NO_MERKLE_ROOT }));
        }

        // 2. validate proof of (receiver, token_id, amount)
        let leaf = crypto::keccak(&(encode_leaf(receiver, token_id, amount)));
        if !verify_proof(&proofs, root, leaf) {
            return Err(AirdropErrors::AirdropError(AirdropError { code: ERROR_INVALID_PROOF }));
        }

        // 3. check claim not already used
        let round  = self.tokenConditionId.get(token);
        let round_u64: u64 = round.to::<u64>();
        let key    = crypto::keccak(&encode_claim_key(round_u64, receiver, token));
        if self.claimed.get(key) {
            return Err(AirdropErrors::AirdropError(AirdropError { code: ERROR_ALREADY_CLAIMED }));
        }
        self.claimed.insert(key, true);

        // 4. transfer
        let erc1155 = IERC1155::from(token);
        let config = Call::new_mutating(self);
        let owner = self.owner.get();
        erc1155
            .safe_transfer_from(self.vm(), config, owner, receiver, token_id, amount, "".into())
            .expect("fail");

        // TODO: event
        Ok(())
    }

    #[payable]
    #[selector(name = "airdropERC1155WithSignature")]
    pub fn airdrop_erc1155_with_signature(
        &mut self,
        req: (B256, Address, U256, Vec<(Address, U256, U256)>),
        signature: [u8; 65],
    ) -> Result<(), AirdropErrors> {
        // 1. Convert tuple to struct for easier access
        let contents: Vec<AirdropContentERC1155> = req.3.iter().map(|(recipient, token_id, amount)| {
            AirdropContentERC1155 {
                recipient: *recipient,
                tokenId: *token_id,
                amount: *amount,
            }
        }).collect();

        let request = AirdropRequestERC1155 {
            uid: req.0,
            tokenAddress: req.1,
            expirationTimestamp: req.2,
            contents,
        };

        // 2. checks
        let expiry = request.expirationTimestamp; 
        let now = U256::from(self.vm().block_timestamp());
        if now > expiry {
            return Err(AirdropErrors::AirdropError(AirdropError { code: ERROR_REQUEST_EXPIRED }));
        }

        let uid_used = self.processed.get(request.uid);
        if uid_used {
            return Err(AirdropErrors::AirdropError(AirdropError { code: ERROR_UID_ALREADY_USED }));
        }

        let owner = self.owner.get();
        if !self.is_valid_sig(&request, &signature, owner) {
            return Err(AirdropErrors::AirdropError(AirdropError { code: ERROR_INVALID_SIGNATURE }));
        }

        // 3. mark uid as processed
        self.processed.insert(request.uid, true);

        // 4. transfer
        let erc1155 = IERC1155::from(request.tokenAddress);

        for c in &request.contents {
            let config = Call::new_mutating(self);
            erc1155
                .safe_transfer_from(self.vm(), config, owner, c.recipient, c.tokenId, c.amount, "".into())
                .expect("fail"); // transfer failed
        }

        // TODO: emit log
        Ok(())
    }

    pub fn set_merkle_root(
        &mut self,
        token: Address,
        token_merkle_root:  B256,
        reset_claim_status: bool,
    ) -> Result<(), AirdropErrors> {
        self.only_owner()?;

        if reset_claim_status || self.tokenConditionId.get(token) == U64::from(0) {
            let next = self.tokenConditionId.get(token) + U64::from(1u8);
            self.tokenConditionId.insert(token, next);
        }

        self.tokenMerkleRoot.insert(token, token_merkle_root);
        
        // TODO: emit log
        Ok(())
    }

    pub fn owner_addr(&self) -> Address { self.owner.get() }

    pub fn domain_separator(&self) -> B256 {
        let name_hash    = crypto::keccak(b"Airdrop");
        let version_hash = crypto::keccak(b"1");
        let chain_bytes: [u8; 32] = U256::from(self.vm().chain_id()).to_be_bytes::<32>();
        let verifying_word: [u8; 32] = address_word(&self.vm().contract_address());

        crypto::keccak(&[
            &EIP712_DOMAIN_TYPEHASH[..],
            &name_hash[..],
            &version_hash[..],
            &chain_bytes[..],
            &verifying_word[..],
        ].concat())
    }
}

impl StylusAirdropERC1155 {
    #[inline(always)]
    fn only_owner(&self) -> Result<(), AirdropErrors> {
        if self.vm().msg_sender() != self.owner.get() {
            return Err(AirdropErrors::AirdropError(AirdropError { code: ERROR_NOT_OWNER }));
        }
        Ok(())
    }

    fn is_valid_sig(&self, req: &AirdropRequestERC1155, sig: &[u8; 65], owner: Address) -> bool {
        let content_hash = hash_content(&req.contents);
        let struct_hash  = hash_request(req, content_hash);

        let digest = crypto::keccak(&[
            b"\x19\x01",
            &self.domain_separator()[..],
            &struct_hash[..],
        ].concat());

        match ecrecover(digest, sig, &*self.vm()) {
            Some(addr) => addr == owner,
            None => false,
        }
    }
}

fn verify_proof(proof: &[B256], root: B256, mut hash: B256) -> bool {
    for p in proof {
        hash = if hash <= *p {
            crypto::keccak(&[hash.as_slice(), p.as_slice()].concat())
        } else {
            crypto::keccak(&[p.as_slice(), hash.as_slice()].concat())
        };
    }
    hash == root
}

/// abi.encodePacked(receiver, token_id, amount)
fn encode_leaf(receiver: Address, token_id: U256, amount: U256) -> [u8; 84] {
    let mut out = [0u8; 84];
    out[..20].copy_from_slice(receiver.as_slice());

    let token_id_bytes: [u8; 32] = token_id.to_be_bytes::<32>();
    out[20..52].copy_from_slice(&token_id_bytes);

    let amount_bytes: [u8; 32] = amount.to_be_bytes::<32>();
    out[52..84].copy_from_slice(&amount_bytes);

    out
}

/// abi.encodePacked(round, receiver, token)
fn encode_claim_key(round: u64, receiver: Address, token: Address) -> [u8; 48] {
    let mut out = [0u8; 48];
    out[..8].copy_from_slice(&round.to_be_bytes());
    out[8..28].copy_from_slice(receiver.as_slice());
    out[28..48].copy_from_slice(token.as_slice());
    out
}

fn address_word(addr: &Address) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(addr.as_slice()); // right-align 20 bytes
    out
}

fn hash_content(contents: &[AirdropContentERC1155]) -> B256 {
    let mut buf = Vec::with_capacity(32 * contents.len());

    for c in contents {
        let leaf = crypto::keccak(
            &[
                CONTENT_TYPEHASH_ERC1155.as_slice(),
                address_word(&c.recipient).as_slice(),
                c.tokenId.to_be_bytes::<32>().as_slice(),
            ]
            .concat(),
        );
        buf.extend_from_slice(
            &leaf.as_slice()[..]
        );
    }
    crypto::keccak(&buf)
}

fn hash_request(req: &AirdropRequestERC1155, contents_hash: B256) -> B256 {
    let token_word = address_word(&req.tokenAddress);

    crypto::keccak(&[
        &REQUEST_TYPEHASH_ERC1155[..],
        &req.uid[..],
        &token_word[..],
        &req.expirationTimestamp.to_be_bytes::<32>()[..],
        &contents_hash[..],
    ].concat())
}

fn ecrecover(digest: B256, sig: &[u8; 65], host: &dyn stylus_sdk::prelude::Host) -> Option<Address> {
    let (r, s, v) = (&sig[0..32], &sig[32..64], sig[64]);

    if v != 27 && v != 28 { return None }

    let mut input = [0u8; 128];
    input[..32].copy_from_slice(&digest.as_slice());
    input[63] = v;
    input[64..96].copy_from_slice(r);
    input[96..128].copy_from_slice(s);

    let precompile_addr = {
        let mut bytes = [0u8; 20];
        bytes[19] = 1; // ecrecover addr
        Address::from(bytes)
    };
    let out = unsafe {
        RawCall::new(host)
            .gas(25_000)                    
            .call(precompile_addr,
                  &input)
    }
    .ok()?;

    if out.len() < 32 { return None }
    let addr = Address::from_slice(&out[12..32]);
    if addr == Address::ZERO { None } else { Some(addr) }
}
