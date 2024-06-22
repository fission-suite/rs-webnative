use anyhow::{anyhow, Result};
use bip39::{Language, Mnemonic, MnemonicType, Seed};
use chrono::Utc;
use rand_chacha::ChaCha12Rng;
use rand_core::SeedableRng;
use rsa::{traits::PublicKeyParts, BigUint, Oaep, RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;
use std::sync::Arc;
use wnfs::{
    private::{
        forest::{hamt::HamtForest, traits::PrivateForest},
        share::{recipient, sharer},
        AccessKey, ExchangeKey, PrivateDirectory, PrivateKey, PrivateNode, PUBLIC_KEY_EXPONENT,
    },
    public::{PublicDirectory, PublicLink},
};
use wnfs_common::blockstore::{Blockstore, InMemoryBlockstore};

//--------------------------------------------------------------------------------------------------
// Example Code
//--------------------------------------------------------------------------------------------------

#[async_std::main]
async fn main() -> Result<()> {
    // We use a single in-memory block store for this example.
    // In practice, there would actually be network transfer involved.
    let store = &InMemoryBlockstore::<64>::new();

    // We create a directory, write something to it and get the private forest
    // and the directory's access key:
    let (mut forest, access_key) = root_dir_setup(store).await?;

    // We write a private share into the private forest for giving access to a
    // seed-derived keypair:
    let mnemonic = setup_seeded_keypair_access(&mut forest, access_key, store).await?;

    println!("seed phrase: {}", mnemonic.phrase());

    // And regain access to our directory,
    // given knowledge of the mnemonic & the private forest:
    let node = regain_access_from_mnemonic(&forest, mnemonic, store).await?;
    let dir = node.as_dir()?;
    let content_bytes = dir
        .read(&["hello".into(), "world".into()], true, &forest, store)
        .await?;
    let content = String::from_utf8_lossy(&content_bytes);

    println!("Contents were: {content}");

    assert_eq!(content, "Hello, World!");

    Ok(())
}

async fn root_dir_setup(store: &impl Blockstore) -> Result<(Arc<HamtForest>, AccessKey)> {
    // We generate a new simple example file system:
    let rng = &mut ChaCha12Rng::from_entropy();
    let forest = &mut HamtForest::new_trusted_rc(rng);
    let root_dir =
        &mut PrivateDirectory::new_and_store(&forest.empty_name(), Utc::now(), forest, store, rng)
            .await?;

    // And write something to it:
    root_dir
        .write(
            &["hello".into(), "world".into()],
            true,
            Utc::now(),
            b"Hello, World!".to_vec(),
            forest,
            store,
            rng,
        )
        .await?;

    // And finally we return the forest and the root directory's access key
    let access_key = root_dir.as_node().store(forest, store, rng).await?;
    Ok((Arc::clone(forest), access_key))
}

async fn setup_seeded_keypair_access(
    forest: &mut Arc<HamtForest>,
    access_key: AccessKey,
    store: &impl Blockstore,
) -> Result<Mnemonic> {
    // Create a random mnemonic and derive a keypair from it
    let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
    let seed = Seed::new(&mnemonic, /* optional password */ "");
    let exchange_keypair = SeededExchangeKey::from_bip39_seed(seed)?;

    // Store the public key inside some public WNFS.
    // Building from scratch in this case. Would actually be stored next to the private forest usually.
    let mut exchange_root = PublicDirectory::new_rc(Utc::now());
    exchange_root
        .write(
            &["main".into(), "v1.exchange_key".into()],
            exchange_keypair.encode_public_key(),
            Utc::now(),
            store,
        )
        .await?;
    let exchange_root = PublicLink::with_rc_dir(exchange_root);

    // The user identity's root DID. In practice this would be e.g. an ed25519 key used
    // for e.g. UCANs or key usually used for authenticating writes.
    let root_did = "did:key:zExample";

    let counter = recipient::find_latest_share_counter(
        0,
        1000,
        &exchange_keypair.encode_public_key(),
        root_did,
        forest,
        store,
    )
    .await?
    .map(|x| x + 1)
    .unwrap_or_default();

    // Write the encrypted AccessKey into the forest
    sharer::share::<PublicExchangeKey>(
        &access_key,
        counter,
        root_did,
        exchange_root,
        forest,
        store,
    )
    .await?;

    Ok(mnemonic)
}

async fn regain_access_from_mnemonic(
    forest: &HamtForest,
    mnemonic: Mnemonic,
    store: &impl Blockstore,
) -> Result<PrivateNode> {
    // Re-derive the same private key from the seed phrase
    let seed = Seed::new(&mnemonic, /* optional password */ "");
    let exchange_keypair = SeededExchangeKey::from_bip39_seed(seed)?;
    let root_did = "did:key:zExample";

    // Re-load private node from forest
    let counter = recipient::find_latest_share_counter(
        0,
        1000,
        &exchange_keypair.encode_public_key(),
        root_did,
        forest,
        store,
    )
    .await?
    .unwrap_or_default();

    let name = sharer::create_share_name(
        counter,
        root_did,
        &exchange_keypair.encode_public_key(),
        forest,
    );

    let node = recipient::receive_share(&name, &exchange_keypair, forest, store).await?;
    let latest_node = node.search_latest(forest, store).await?;
    Ok(latest_node)
}

//--------------------------------------------------------------------------------------------------
// Structs & Implementations
//--------------------------------------------------------------------------------------------------

struct SeededExchangeKey(RsaPrivateKey);

struct PublicExchangeKey(RsaPublicKey);

impl SeededExchangeKey {
    pub fn from_bip39_seed(seed: Seed) -> Result<Self> {
        let seed_bytes: [u8; 32] = seed.as_bytes()[..32].try_into()?;
        let rng = &mut ChaCha12Rng::from_seed(seed_bytes);
        let private_key = RsaPrivateKey::new(rng, 2048)?;
        Ok(Self(private_key))
    }

    pub fn encode_public_key(&self) -> Vec<u8> {
        self.0.n().to_bytes_be()
    }
}

impl PrivateKey for SeededExchangeKey {
    async fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let padding = Oaep::new::<Sha256>();
        self.0.decrypt(padding, ciphertext).map_err(|e| anyhow!(e))
    }
}

impl ExchangeKey for PublicExchangeKey {
    async fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let padding = Oaep::new::<Sha256>();
        self.0
            .encrypt(&mut ChaCha12Rng::from_entropy(), padding, data)
            .map_err(|e| anyhow!(e))
    }

    async fn from_modulus(modulus: &[u8]) -> Result<Self> {
        let n = BigUint::from_bytes_be(modulus);
        let e = BigUint::from(PUBLIC_KEY_EXPONENT);

        Ok(Self(rsa::RsaPublicKey::new(n, e).map_err(|e| anyhow!(e))?))
    }
}
