/*
 * Unified ADDSUBCHAIN-E benchmarks using consolidated implementation
 */

#include <benchmark/benchmark.h>
#include "abeliangroup_unified.h"
#include "edwards25519.h"
#include "fastrng.h"
#include "pastacurves.h"
#include "primefield.h"

using namespace blacknet::crypto;
using namespace blacknet::crypto::abeliangroup;

static FastDRG rng;

// ============================================================================
// UNIFIED ADDSUBCHAIN BENCHMARKS
// ============================================================================

template<AbelianGroupElement ECG, ScalarType Scalar>
static void BM_UnifiedMultilinearConstraints(benchmark::State& state) {
    auto engine = create_addsubchain_engine<ECG, Scalar>("multilinear");
    auto a = ECG::random(rng);
    auto b = Scalar::random(rng);
    
    for (auto _ : state) {
        auto result = engine->multiply_with_constraints(a, b);
        benchmark::DoNotOptimize(result);
        benchmark::ClobberMemory();
    }
}
BENCHMARK(BM_UnifiedMultilinearConstraints<PallasGroupJacobian, VestaField>);
BENCHMARK(BM_UnifiedMultilinearConstraints<Edwards25519GroupExtended, Field25519>);

template<AbelianGroupElement ECG, ScalarType Scalar>
static void BM_UnifiedZkVMConstraints(benchmark::State& state) {
    auto engine = create_addsubchain_engine<ECG, Scalar>("zkvm");
    auto a = ECG::random(rng);
    auto b = Scalar::random(rng);
    
    for (auto _ : state) {
        auto result = engine->multiply_with_constraints(a, b);
        benchmark::DoNotOptimize(result);
        benchmark::ClobberMemory();
    }
}
BENCHMARK(BM_UnifiedZkVMConstraints<PallasGroupJacobian, VestaField>);
BENCHMARK(BM_UnifiedZkVMConstraints<Edwards25519GroupExtended, Field25519>);

template<AbelianGroupElement ECG, ScalarType Scalar>
static void BM_UnifiedSimpleMultiplication(benchmark::State& state) {
    auto engine = create_addsubchain_engine<ECG, Scalar>("multilinear");
    auto a = ECG::random(rng);
    auto b = Scalar::random(rng);
    
    for (auto _ : state) {
        auto result = engine->multiply_simple(a, b);
        benchmark::DoNotOptimize(result);
        benchmark::ClobberMemory();
    }
}
BENCHMARK(BM_UnifiedSimpleMultiplication<PallasGroupJacobian, VestaField>);
BENCHMARK(BM_UnifiedSimpleMultiplication<Edwards25519GroupExtended, Field25519>);

// Legacy compatibility benchmark
template<AbelianGroupElement ECG, ScalarType Scalar>
static void BM_LegacyMultiply(benchmark::State& state) {
    auto a = ECG::random(rng);
    auto b = Scalar::random(rng);
    
    for (auto _ : state) {
        auto result = multiply(a, b);
        benchmark::DoNotOptimize(result);
        benchmark::ClobberMemory();
    }
}
BENCHMARK(BM_LegacyMultiply<PallasGroupJacobian, VestaField>);
BENCHMARK(BM_LegacyMultiply<Edwards25519GroupExtended, Field25519>);

// Strategy comparison benchmark
template<AbelianGroupElement ECG, ScalarType Scalar>
static void BM_StrategyComparison(benchmark::State& state) {
    auto multilinear_engine = create_addsubchain_engine<ECG, Scalar>("multilinear");
    auto zkvm_engine = create_addsubchain_engine<ECG, Scalar>("zkvm");
    auto a = ECG::random(rng);
    auto b = Scalar::random(rng);
    
    for (auto _ : state) {
        auto multilinear_result = multilinear_engine->multiply_with_constraints(a, b);
        auto zkvm_result = zkvm_engine->multiply_with_constraints(a, b);
        
        benchmark::DoNotOptimize(multilinear_result);
        benchmark::DoNotOptimize(zkvm_result);
        benchmark::ClobberMemory();
    }
}
BENCHMARK(BM_StrategyComparison<PallasGroupJacobian, VestaField>);
BENCHMARK(BM_StrategyComparison<Edwards25519GroupExtended, Field25519>);

// Memory pool efficiency benchmark
template<AbelianGroupElement ECG, ScalarType Scalar>
static void BM_MemoryPoolEfficiency(benchmark::State& state) {
    auto engine = create_addsubchain_engine<ECG, Scalar>("multilinear");
    auto a = ECG::random(rng);
    auto b = Scalar::random(rng);
    
    // Pre-warm the memory pool
    auto warmup_result = engine->multiply_with_constraints(a, b);
    engine->get_memory_pool().reset();
    
    for (auto _ : state) {
        auto result = engine->multiply_with_constraints(a, b);
        auto stats = engine->get_memory_pool().get_stats();
        
        benchmark::DoNotOptimize(result);
        benchmark::DoNotOptimize(stats);
        benchmark::ClobberMemory();
        
        // Reset pool for next iteration
        engine->get_memory_pool().reset();
    }
}
BENCHMARK(BM_MemoryPoolEfficiency<PallasGroupJacobian, VestaField>);
BENCHMARK(BM_MemoryPoolEfficiency<Edwards25519GroupExtended, Field25519>);

// ============================================================================
// COMPARISON WITH LEGACY IMPLEMENTATION BENCHMARKS
// ============================================================================

// Direct elliptic curve operations (baseline)
template<AbelianGroupElement ECG>
static void BM_DirectEllipticCurveAdd(benchmark::State& state) {
    auto a = ECG::random(rng);
    auto b = ECG::random(rng);

    for (auto _ : state) {
        a = a + b;
        benchmark::DoNotOptimize(a);
        benchmark::DoNotOptimize(b);
        benchmark::ClobberMemory();
    }
}
BENCHMARK(BM_DirectEllipticCurveAdd<PallasGroupJacobian>);
BENCHMARK(BM_DirectEllipticCurveAdd<Edwards25519GroupExtended>);

template<AbelianGroupElement ECG>
static void BM_DirectEllipticCurveDbl(benchmark::State& state) {
    auto a = ECG::random(rng);

    for (auto _ : state) {
        a = a.douple();
        benchmark::DoNotOptimize(a);
        benchmark::ClobberMemory();
    }
}
BENCHMARK(BM_DirectEllipticCurveDbl<PallasGroupJacobian>);
BENCHMARK(BM_DirectEllipticCurveDbl<Edwards25519GroupExtended>);

// Blacknet semigroup scalar multiplication (baseline comparison)
template<AbelianGroupElement ECG, ScalarType Scalar>
static void BM_SemigroupMultiply(benchmark::State& state) {
    auto a = ECG::random(rng);
    auto b = Scalar::random(rng);

    for (auto _ : state) {
        auto result = semigroup::multiply(a, b);
        benchmark::DoNotOptimize(result);
        benchmark::ClobberMemory();
    }
}
BENCHMARK(BM_SemigroupMultiply<PallasGroupJacobian, VestaField>);
BENCHMARK(BM_SemigroupMultiply<Edwards25519GroupExtended, Field25519>);

// Comprehensive performance comparison
template<AbelianGroupElement ECG, ScalarType Scalar>
static void BM_ComprehensiveComparison(benchmark::State& state) {
    auto engine = create_addsubchain_engine<ECG, Scalar>("multilinear");
    auto a = ECG::random(rng);
    auto b = Scalar::random(rng);
    
    for (auto _ : state) {
        // Test all approaches
        auto semigroup_result = semigroup::multiply(a, b);
        auto unified_simple = engine->multiply_simple(a, b);
        auto unified_constraints = engine->multiply_with_constraints(a, b);
        auto legacy_result = multiply(a, b);
        
        benchmark::DoNotOptimize(semigroup_result);
        benchmark::DoNotOptimize(unified_simple);
        benchmark::DoNotOptimize(unified_constraints);
        benchmark::DoNotOptimize(legacy_result);
        benchmark::ClobberMemory();
    }
}
BENCHMARK(BM_ComprehensiveComparison<PallasGroupJacobian, VestaField>);
BENCHMARK(BM_ComprehensiveComparison<Edwards25519GroupExtended, Field25519>);