/*
 * Copyright (c) 2024-2025 Pavel Vasin
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include <benchmark/benchmark.h>

#include "edwards25519.h"
#include "fastrng.h"
#include "pastacurves.h"
#include "abeliangroup.h"
#include "primefield.h"
#include <chrono>

using namespace blacknet::crypto;

static FastDRG rng;

template<typename ECG>
static void BM_EllipticCurveAdd(benchmark::State& state) {
    auto a = ECG::random(rng);
    auto b = ECG::random(rng);

    for (auto _ : state) {
        a = a + b;

        benchmark::DoNotOptimize(a);
        benchmark::DoNotOptimize(b);
        benchmark::ClobberMemory();
    }
}
BENCHMARK(BM_EllipticCurveAdd<PallasGroupJacobian>);
BENCHMARK(BM_EllipticCurveAdd<Edwards25519GroupExtended>);

template<typename ECG>
static void BM_EllipticCurveDbl(benchmark::State& state) {
    auto a = ECG::random(rng);

    for (auto _ : state) {
        a = a.douple();

        benchmark::DoNotOptimize(a);
        benchmark::ClobberMemory();
    }
}
BENCHMARK(BM_EllipticCurveDbl<PallasGroupJacobian>);
BENCHMARK(BM_EllipticCurveDbl<Edwards25519GroupExtended>);

template<typename ECG>
static void BM_EllipticCurveSub(benchmark::State& state) {
    auto a = ECG::random(rng);
    auto b = ECG::random(rng);

    for (auto _ : state) {
        a = a - b;

        benchmark::DoNotOptimize(a);
        benchmark::DoNotOptimize(b);
        benchmark::ClobberMemory();
    }
}
BENCHMARK(BM_EllipticCurveSub<PallasGroupJacobian>);
BENCHMARK(BM_EllipticCurveSub<Edwards25519GroupExtended>);

template<typename ECG>
static void BM_EllipticCurveMul(benchmark::State& state) {
    auto a = ECG::random(rng);
    auto b = ECG::Scalar::random(rng);

    for (auto _ : state) {
        a = a * b;

        benchmark::DoNotOptimize(a);
        benchmark::DoNotOptimize(b);
        benchmark::ClobberMemory();
    }
}
BENCHMARK(BM_EllipticCurveMul<PallasGroupJacobian>);
BENCHMARK(BM_EllipticCurveMul<Edwards25519GroupExtended>);

// ADDSUBCHAIN-E Constraint Generation Benchmarks

template<typename ECG>
static void BM_EllipticCurveConstraints(benchmark::State& state) {
    auto a = ECG::random(rng);
    auto b = ECG::Scalar::random(rng);
    
    for (auto _ : state) {
        abeliangroup::ProofSystemOptimizedMult<ECG, typename ECG::Scalar, typename ECG::Base> mult;
        auto constraints = mult.generate_constraint_system(a, b);
        
        benchmark::DoNotOptimize(constraints.linear_constraints);
        benchmark::DoNotOptimize(constraints.quadratic_constraints);
        benchmark::ClobberMemory();
    }
}
BENCHMARK(BM_EllipticCurveConstraints<PallasGroupJacobian>);
BENCHMARK(BM_EllipticCurveConstraints<Edwards25519GroupExtended>);

template<typename ECG>
static void BM_EllipticCurveMultilinearConstraints(benchmark::State& state) {
    auto a = ECG::random(rng);
    auto b = ECG::Scalar::random(rng);
    
    for (auto _ : state) {
        abeliangroup::MultilinearScalarMult<ECG, typename ECG::Scalar> mult;
        auto simple_constraints = mult.multiply_to_constraints(a, b);
        
        benchmark::DoNotOptimize(simple_constraints);
        benchmark::ClobberMemory();
    }
}
BENCHMARK(BM_EllipticCurveMultilinearConstraints<PallasGroupJacobian>);
BENCHMARK(BM_EllipticCurveMultilinearConstraints<Edwards25519GroupExtended>);

template<typename ECG>
static void BM_EllipticCurveNeoConstraints(benchmark::State& state) {
    auto a = ECG::random(rng);
    auto b = ECG::Scalar::random(rng);
    
    for (auto _ : state) {
        abeliangroup::NeoOptimizedMult<ECG, typename ECG::Scalar, typename ECG::Base> neo_mult;
        auto bit_granular_cs = neo_mult.generate_constraint_system(a, b);
        
        benchmark::DoNotOptimize(bit_granular_cs.bit_constraints);
        benchmark::DoNotOptimize(bit_granular_cs.field_constraints);
        benchmark::DoNotOptimize(bit_granular_cs.goldilocks_constraints);
        benchmark::ClobberMemory();
    }
}
BENCHMARK(BM_EllipticCurveNeoConstraints<PallasGroupJacobian>);
BENCHMARK(BM_EllipticCurveNeoConstraints<Edwards25519GroupExtended>);

template<typename ECG>
static void BM_EllipticCurveStreamingConstraints(benchmark::State& state) {
    auto a = ECG::random(rng);
    auto b = ECG::Scalar::random(rng);
    
    for (auto _ : state) {
        abeliangroup::StreamingMultilinearMult<ECG, typename ECG::Scalar> streaming_mult;
        auto chunk_constraints = streaming_mult.process_in_chunks(a, b);
        
        benchmark::DoNotOptimize(chunk_constraints);
        benchmark::ClobberMemory();
    }
}
BENCHMARK(BM_EllipticCurveStreamingConstraints<PallasGroupJacobian>);
BENCHMARK(BM_EllipticCurveStreamingConstraints<Edwards25519GroupExtended>);

// Simplified constraint generation benchmark (no timing overhead)
template<typename ECG>
static void BM_ConstraintVsDirectComparison(benchmark::State& state) {
    auto a = ECG::random(rng);
    auto b = ECG::Scalar::random(rng);
    
    for (auto _ : state) {
        abeliangroup::MultilinearScalarMult<ECG, typename ECG::Scalar> mult;
        auto constraints = mult.multiply_to_constraints(a, b);
        auto result = a * b;
        
        benchmark::DoNotOptimize(constraints);
        benchmark::DoNotOptimize(result);
        benchmark::ClobberMemory();
    }
}
BENCHMARK(BM_ConstraintVsDirectComparison<PallasGroupJacobian>);
BENCHMARK(BM_ConstraintVsDirectComparison<Edwards25519GroupExtended>);

// Simplified approach comparison (no timing overhead)
template<typename ECG>
static void BM_ConstraintApproachComparison(benchmark::State& state) {
    auto a = ECG::random(rng);
    auto b = ECG::Scalar::random(rng);
    
    for (auto _ : state) {
        abeliangroup::MultilinearScalarMult<ECG, typename ECG::Scalar> mult;
        auto multi_constraints = mult.multiply_to_constraints(a, b);
        
        abeliangroup::NeoOptimizedMult<ECG, typename ECG::Scalar, typename ECG::Base> neo_mult;
        auto neo_cs = neo_mult.generate_constraint_system(a, b);
        
        abeliangroup::StreamingMultilinearMult<ECG, typename ECG::Scalar> stream_mult;
        auto stream_chunks = stream_mult.process_in_chunks(a, b);
        
        benchmark::DoNotOptimize(multi_constraints);
        benchmark::DoNotOptimize(neo_cs);
        benchmark::DoNotOptimize(stream_chunks);
        benchmark::ClobberMemory();
    }
}
BENCHMARK(BM_ConstraintApproachComparison<PallasGroupJacobian>);
BENCHMARK(BM_ConstraintApproachComparison<Edwards25519GroupExtended>);

// ==================== NEO PAPER LEVERAGE BENCHMARKS ====================

// Simplified LatticeFold constraint verification (no metrics overhead)
template<typename ECG>
static void BM_LatticeFoldConstraintVerification(benchmark::State& state) {
    auto a = ECG::random(rng);
    auto b = ECG::Scalar::random(rng);
    
    for (auto _ : state) {
        abeliangroup::NeoOptimizedMult<ECG, typename ECG::Scalar, typename ECG::Base> neo_mult;
        auto neo_cs = neo_mult.generate_constraint_system(a, b);
        
        benchmark::DoNotOptimize(neo_cs);
        benchmark::ClobberMemory();
    }
}
BENCHMARK(BM_LatticeFoldConstraintVerification<PallasGroupJacobian>);
BENCHMARK(BM_LatticeFoldConstraintVerification<Edwards25519GroupExtended>);

// Simplified Neo commitment comparison (no cost calculations)
template<typename ECG>
static void BM_NeoCommitmentCostOptimization(benchmark::State& state) {
    auto a = ECG::random(rng);
    auto b = ECG::Scalar::random(rng);
    
    for (auto _ : state) {
        abeliangroup::MultilinearScalarMult<ECG, typename ECG::Scalar> baseline_mult;
        auto baseline_constraints = baseline_mult.multiply_to_constraints(a, b);
        
        abeliangroup::NeoOptimizedMult<ECG, typename ECG::Scalar, typename ECG::Base> neo_mult;
        auto neo_cs = neo_mult.generate_constraint_system(a, b);
        
        benchmark::DoNotOptimize(baseline_constraints);
        benchmark::DoNotOptimize(neo_cs);
        benchmark::ClobberMemory();
    }
}
BENCHMARK(BM_NeoCommitmentCostOptimization<PallasGroupJacobian>);
BENCHMARK(BM_NeoCommitmentCostOptimization<Edwards25519GroupExtended>);

// Simplified post-quantum comparison (no simulation overhead)
template<typename ECG>
static void BM_PostQuantumSecurityOverhead(benchmark::State& state) {
    auto a = ECG::random(rng);
    auto b = ECG::Scalar::random(rng);
    
    for (auto _ : state) {
        abeliangroup::NeoOptimizedMult<ECG, typename ECG::Scalar, typename ECG::Base> classical_mult;
        auto classical_cs = classical_mult.generate_constraint_system(a, b);
        
        benchmark::DoNotOptimize(classical_cs);
        benchmark::ClobberMemory();
    }
}
BENCHMARK(BM_PostQuantumSecurityOverhead<PallasGroupJacobian>);
BENCHMARK(BM_PostQuantumSecurityOverhead<Edwards25519GroupExtended>);

// Performance comparison: All constraint generation approaches
template<typename ECG>
static void BM_AllConstraintApproaches(benchmark::State& state) {
    auto a = ECG::random(rng);
    auto b = ECG::Scalar::random(rng);
    
    for (auto _ : state) {
        abeliangroup::MultilinearScalarMult<ECG, typename ECG::Scalar> multi_mult;
        auto multi_constraints = multi_mult.multiply_to_constraints(a, b);
        
        abeliangroup::NeoOptimizedMult<ECG, typename ECG::Scalar, typename ECG::Base> neo_mult;
        auto neo_cs = neo_mult.generate_constraint_system(a, b);
        
        abeliangroup::StreamingMultilinearMult<ECG, typename ECG::Scalar> stream_mult;
        auto stream_chunks = stream_mult.process_in_chunks(a, b);
        
        benchmark::DoNotOptimize(multi_constraints);
        benchmark::DoNotOptimize(neo_cs);
        benchmark::DoNotOptimize(stream_chunks);
        benchmark::ClobberMemory();
    }
}
BENCHMARK(BM_AllConstraintApproaches<PallasGroupJacobian>);
BENCHMARK(BM_AllConstraintApproaches<Edwards25519GroupExtended>);
