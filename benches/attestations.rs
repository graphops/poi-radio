use criterion::criterion_main;

extern crate criterion;

mod attestation {
    use criterion::{black_box, criterion_group, Criterion};
    use poi_radio::operator::attestation::{
        compare_attestations, local_comparison_point, update_blocks, Attestation,
    };
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex as SyncMutex},
    };

    criterion_group!(
        benches,
        update_block_bench,
        update_attestations_bench,
        compare_attestations_bench,
        comparison_point_bench
    );

    fn update_block_bench(c: &mut Criterion) {
        let mut blocks: HashMap<u64, Vec<Attestation>> = black_box(black_box(HashMap::new()));
        black_box(blocks.insert(
            42,
            vec![black_box(Attestation::new(
                "default".to_string(),
                0.0,
                Vec::new(),
                Vec::new(),
            ))],
        ));

        c.bench_function("update_block", |b| {
            b.iter(|| {
                update_blocks(
                    42,
                    &blocks,
                    "awesome-npoi".to_string(),
                    0.0,
                    "0xadd3".to_string(),
                    1,
                )
            })
        });
    }

    fn update_attestations_bench(c: &mut Criterion) {
        let attestation = black_box(Attestation::new(
            "awesome-npoi".to_string(),
            0.0,
            vec!["0xa1".to_string()],
            vec![2],
        ));

        c.bench_function("update_attestation", |b| {
            b.iter(|| Attestation::update(&attestation, "0xa2".to_string(), 1.0, 1))
        });
    }

    fn compare_attestations_bench(c: &mut Criterion) {
        let mut remote_blocks: HashMap<u64, Vec<Attestation>> = black_box(HashMap::new());
        let mut local_blocks: HashMap<u64, Attestation> = black_box(HashMap::new());

        let remote = black_box(Attestation::new(
            "awesome-npoi".to_string(),
            0.0,
            vec!["0xa1".to_string()],
            vec![0],
        ));
        black_box(remote_blocks.insert(42, vec![remote]));

        let local = black_box(Attestation::new(
            "awesome-npoi".to_string(),
            0.0,
            Vec::new(),
            vec![0],
        ));
        black_box(local_blocks.insert(42, local));

        let mut remote_attestations: HashMap<String, HashMap<u64, Vec<Attestation>>> =
            black_box(HashMap::new());
        let mut local_attestations: HashMap<String, HashMap<u64, Attestation>> =
            black_box(HashMap::new());

        black_box(remote_attestations.insert("my-awesome-hash".to_string(), remote_blocks));
        black_box(local_attestations.insert("my-awesome-hash".to_string(), local_blocks));

        c.bench_function("compare_attestations", |b| {
            b.iter(|| {
                compare_attestations(
                    42,
                    black_box(remote_attestations.clone()),
                    black_box(Arc::new(SyncMutex::new(local_attestations.clone()))),
                    "my-awesome-hash",
                )
            })
        });
    }

    fn comparison_point_bench(c: &mut Criterion) {
        let mut local_blocks: HashMap<u64, Attestation> = black_box(HashMap::new());
        let attestation1 = black_box(Attestation::new(
            "awesome-npoi".to_string(),
            0.0,
            vec!["0xa1".to_string()],
            vec![2],
        ));

        let attestation2 = black_box(Attestation::new(
            "awesome-npoi".to_string(),
            0.0,
            vec!["0xa2".to_string()],
            vec![4],
        ));

        let attestation3 = black_box(Attestation::new(
            "awesome-npoi".to_string(),
            1.0,
            vec!["0xa3".to_string()],
            vec![6],
        ));

        black_box(local_blocks.insert(42, attestation1));
        black_box(local_blocks.insert(43, attestation2));
        black_box(local_blocks.insert(44, attestation3));

        let mut local_attestations: HashMap<String, HashMap<u64, Attestation>> =
            black_box(HashMap::new());
        black_box(local_attestations.insert("hash".to_string(), local_blocks.clone()));
        black_box(local_attestations.insert("hash2".to_string(), local_blocks));
        let local: Arc<SyncMutex<HashMap<String, HashMap<u64, Attestation>>>> =
            black_box(Arc::new(SyncMutex::new(local_attestations)));

        c.bench_function("comparison_point", |b| {
            b.iter(|| local_comparison_point(black_box(local.clone()), "hash".to_string(), 120))
        });
    }
}
criterion_main!(attestation::benches);
