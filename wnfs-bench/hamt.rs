use async_std::task;
use criterion::{
    async_executor::AsyncStdExecutor, black_box, criterion_group, criterion_main, BatchSize,
    Criterion, Throughput,
};
use proptest::{arbitrary::any, collection::vec, test_runner::TestRunner};
use std::cmp;
use wnfs_common::{
    blockstore::{block::Block as _, Blockstore, InMemoryBlockstore},
    utils::{Arc, Sampleable},
    Blake3Block, Link, Storable, StoreIpld,
};
use wnfs_hamt::{
    diff, merge,
    strategies::{generate_kvs, node_from_kvs, node_from_operations, operations},
    Hamt, Node,
};

fn node_set(c: &mut Criterion) {
    let mut runner = TestRunner::deterministic();
    let store = InMemoryBlockstore::<64>::new();
    let operations = operations(any::<[u8; 32]>(), any::<u64>(), 1_000_000).sample(&mut runner);
    let node =
        &async_std::task::block_on(async { node_from_operations(&operations, &store).await })
            .expect("Couldn't setup HAMT node from operations");

    let store = Arc::new(store);

    c.bench_function("node set", |b| {
        b.to_async(AsyncStdExecutor).iter_batched(
            || {
                let store = Arc::clone(&store);
                let kv = (any::<[u8; 32]>(), any::<u64>()).sample(&mut runner);
                (store, kv)
            },
            |(store, (key, value))| async move {
                Arc::clone(node)
                    .set(key, value, store.as_ref())
                    .await
                    .unwrap();
                black_box(());
            },
            BatchSize::SmallInput,
        );
    });
}

fn node_set_consecutive(c: &mut Criterion) {
    let mut runner = TestRunner::deterministic();

    c.bench_function("node set 1000 consecutive", |b| {
        b.to_async(AsyncStdExecutor).iter_batched(
            || {
                let store = InMemoryBlockstore::<64>::new();
                let operations =
                    operations(any::<[u8; 32]>(), any::<u64>(), 1000).sample(&mut runner);
                let node = async_std::task::block_on(async {
                    node_from_operations(&operations, &store).await
                })
                .expect("Couldn't setup HAMT node from operations");

                let kvs = vec((any::<[u8; 32]>(), any::<u64>()), 1000).sample(&mut runner);
                (node, store, kvs)
            },
            |(mut node, store, kvs)| async move {
                for (key, value) in kvs {
                    node.set(key, value, &store).await.unwrap();
                    black_box(());
                }
            },
            BatchSize::SmallInput,
        );
    });
}

fn node_load_get(c: &mut Criterion) {
    let store = InMemoryBlockstore::<64>::new();
    let cid = async_std::task::block_on(async {
        let mut node = Arc::new(<Node<_, _>>::default());
        for i in 0..50 {
            node.set(i.to_string(), i, &store).await.unwrap();
        }

        Hamt::with_root(node).store(&store).await.unwrap()
    });

    c.bench_function("node load and get", |b| {
        b.to_async(AsyncStdExecutor).iter(|| async {
            let hamt = Hamt::<String, i32>::load(&cid, &store).await.unwrap();

            for i in 0..50 {
                assert!(hamt
                    .root
                    .get(&i.to_string(), &store)
                    .await
                    .unwrap()
                    .is_some());
            }
        })
    });
}

fn node_load_remove(c: &mut Criterion) {
    let store = InMemoryBlockstore::<64>::new();
    let cid = async_std::task::block_on(async {
        let mut node = Arc::new(<Node<_, _>>::default());
        for i in 0..50 {
            node.set(i.to_string(), i, &store).await.unwrap();
        }

        Hamt::with_root(node).store(&store).await.unwrap()
    });

    c.bench_function("node load and remove", |b| {
        b.to_async(AsyncStdExecutor).iter(|| async {
            let mut hamt = black_box(Hamt::<String, i32>::load(&cid, &store).await.unwrap());

            for i in 0..50 {
                let value = hamt.root.remove(&i.to_string(), &store).await.unwrap();
                assert!(value.is_some());
            }
        })
    });
}

fn hamt_load_decode(c: &mut Criterion) {
    let store = InMemoryBlockstore::<64>::new();
    let (cid, bytes) = async_std::task::block_on(async {
        let mut node = Arc::new(<Node<_, _>>::default());
        for i in 0..50 {
            node.set(i.to_string(), i, &store).await.unwrap();
        }

        let (encoded_hamt, codec) = Hamt::with_root(node)
            .to_serializable(&store)
            .await
            .unwrap()
            .encode_ipld()
            .unwrap();

        let block = Blake3Block::new(codec, encoded_hamt.clone());
        let cid = block.cid().unwrap();
        store.put(block).await.unwrap();

        (cid, encoded_hamt)
    });

    let mut group = c.benchmark_group("hamt load and decode");
    group.throughput(Throughput::Bytes(bytes.len() as u64));
    group.bench_function("0", |b| {
        b.to_async(AsyncStdExecutor).iter(|| async {
            black_box(Hamt::<String, i32>::load(&cid, &store).await.unwrap());
        })
    });
    group.finish();
}

fn hamt_set_encode(c: &mut Criterion) {
    c.bench_function("hamt set and encode", |b| {
        b.to_async(AsyncStdExecutor).iter_batched(
            || {
                (
                    InMemoryBlockstore::<64>::new(),
                    Arc::new(<Node<_, _>>::default()),
                )
            },
            |(store, mut node)| async move {
                for i in 0..50 {
                    node.set(i.to_string(), i, &store).await.unwrap();
                }

                let hamt = Hamt::with_root(node);

                black_box(
                    hamt.to_serializable(&store)
                        .await
                        .unwrap()
                        .encode_ipld()
                        .unwrap(),
                );
            },
            BatchSize::SmallInput,
        )
    });
}

fn hamt_diff(c: &mut Criterion) {
    let mut runner = TestRunner::deterministic();

    c.bench_function("hamt diff", |b| {
        b.to_async(AsyncStdExecutor).iter_batched(
            || {
                let store = InMemoryBlockstore::<64>::new();
                let kvs1 = generate_kvs("[a-z0-9]{1,3}", 0u64..1000, 0..100).sample(&mut runner);
                let kvs2 = generate_kvs("[a-z0-9]{1,3}", 0u64..1000, 0..100).sample(&mut runner);
                let (node1, node2) = task::block_on(async {
                    (
                        node_from_kvs(kvs1, &store).await.unwrap(),
                        node_from_kvs(kvs2, &store).await.unwrap(),
                    )
                });
                (store, (node1, node2))
            },
            |(store, (node1, node2))| async move {
                black_box(
                    diff(Link::from(node1), Link::from(node2), &store)
                        .await
                        .unwrap(),
                );
            },
            BatchSize::SmallInput,
        );
    });
}

fn hamt_merge(c: &mut Criterion) {
    let mut runner = TestRunner::deterministic();

    c.bench_function("hamt merge", |b| {
        b.to_async(AsyncStdExecutor).iter_batched(
            || {
                let store = InMemoryBlockstore::<64>::new();
                let kvs1 = generate_kvs("[a-z0-9]{1,3}", 0u64..1000, 0..100).sample(&mut runner);
                let kvs2 = generate_kvs("[a-z0-9]{1,3}", 0u64..1000, 0..100).sample(&mut runner);
                let (node1, node2) = task::block_on(async {
                    (
                        node_from_kvs(kvs1, &store).await.unwrap(),
                        node_from_kvs(kvs2, &store).await.unwrap(),
                    )
                });
                (store, (node1, node2))
            },
            |(store, (node1, node2))| async move {
                black_box(
                    merge(
                        Link::from(node1),
                        Link::from(node2),
                        |a, b| Ok(cmp::min(*a, *b)),
                        &store,
                    )
                    .await
                    .unwrap(),
                );
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(
    benches,
    node_set,
    node_set_consecutive,
    node_load_get,
    node_load_remove,
    hamt_load_decode,
    hamt_set_encode,
    hamt_diff,
    hamt_merge
);

criterion_main!(benches);
