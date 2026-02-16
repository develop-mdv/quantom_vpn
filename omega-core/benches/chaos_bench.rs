use criterion::{black_box, criterion_group, criterion_main, Criterion};
use omega_core::chaos::ChaosPrng;

fn bench_chaos_next(c: &mut Criterion) {
    let mut prng = ChaosPrng::new(0xDEAD_BEEF_CAFE_BABEu64);
    c.bench_function("chaos_next", |b| {
        b.iter(|| {
            black_box(prng.next());
        })
    });
}

fn bench_chaos_get_target_size(c: &mut Criterion) {
    let mut prng = ChaosPrng::new(0xDEAD_BEEF_CAFE_BABEu64);
    c.bench_function("chaos_get_target_size", |b| {
        b.iter(|| {
            black_box(prng.get_target_size());
        })
    });
}

fn bench_chaos_batch_1000(c: &mut Criterion) {
    let mut prng = ChaosPrng::new(0xDEAD_BEEF_CAFE_BABEu64);
    c.bench_function("chaos_batch_1000_sizes", |b| {
        b.iter(|| {
            for _ in 0..1000 {
                black_box(prng.get_target_size());
            }
        })
    });
}

criterion_group!(benches, bench_chaos_next, bench_chaos_get_target_size, bench_chaos_batch_1000);
criterion_main!(benches);
