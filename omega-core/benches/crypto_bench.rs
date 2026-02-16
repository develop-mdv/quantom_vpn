use criterion::{criterion_group, criterion_main, Criterion, Throughput, BenchmarkId};
use omega_core::crypto::SessionKeys;
use std::hint::black_box;

fn crypto_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("chacha20_poly1305");
    
    // Create keys
    let shared_secret = vec![0u8; 32];
    // Client keys (init = true handles nonces differently?) 
    // Actually from_shared_secret(..., is_server) affects key splitting.
    let mut sender_keys = SessionKeys::from_shared_secret(&shared_secret, false).unwrap();
    let mut receiver_keys = SessionKeys::from_shared_secret(&shared_secret, true).unwrap();
    
    let aad = b"omega_header_aad";

    for size in [100, 500, 1200].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        
        // Encryption Benchmark
        group.bench_with_input(BenchmarkId::new("encrypt", size), size, |b, &size| {
            // Fresh keys for this bench
            let mut sender_keys = SessionKeys::from_shared_secret(&shared_secret, false).unwrap();
            
            // Prepare buffer with capacity for tag
            let mut buffer = vec![0u8; size + 16]; 
            // Fill with dummy data
            buffer[..size].fill(0xAA);
            unsafe { buffer.set_len(size); }
            
            b.iter(|| {
                // Return buffer to original size
                unsafe { buffer.set_len(size); }
                
                // Perform encryption (increments seq)
                sender_keys.encrypt_in_place(black_box(&mut buffer), black_box(aad)).unwrap();
            });
        });

        // Decryption Benchmark
        group.bench_with_input(BenchmarkId::new("decrypt", size), size, |b, &size| {
            // Fresh keys for setup
            let mut sender_keys = SessionKeys::from_shared_secret(&shared_secret, false).unwrap();
            let mut receiver_keys = SessionKeys::from_shared_secret(&shared_secret, true).unwrap();
            
            // Prepare an encrypted packet first
            let mut encrypted = vec![0u8; size]; // Plaintext size
            encrypted.fill(0xBB);
            sender_keys.encrypt_in_place(&mut encrypted, aad).unwrap();
            // Now 'encrypted' has size + 16 bytes and used seq=0.
            
            b.iter_batched(
                || encrypted.clone(), 
                |mut packet| {
                    // Decrypt using seq 0 (since we just encrypted with seq 0 above)
                    receiver_keys.decrypt_in_place(black_box(&mut packet), 0, black_box(aad)).unwrap();
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

criterion_group!(benches, crypto_benchmark);
criterion_main!(benches);
