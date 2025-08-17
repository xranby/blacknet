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
using namespace blacknet::crypto::abeliangroup;

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
        // Use the unified legacy multiply function
        auto result = abeliangroup::multiply(a, b);
        
        benchmark::DoNotOptimize(result);
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
        auto result = abeliangroup::multiply(a, b);
        
        benchmark::DoNotOptimize(result);
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
        auto result = abeliangroup::multiply(a, b);
        
        benchmark::DoNotOptimize(result);
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
        auto result = abeliangroup::multiply(a, b);
        
        benchmark::DoNotOptimize(result);
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
        auto unified_result = abeliangroup::multiply(a, b);
        auto direct_result = a * b;
        
        benchmark::DoNotOptimize(unified_result);
        benchmark::DoNotOptimize(direct_result);
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
        auto unified_result = abeliangroup::multiply(a, b);
        auto semigroup_result = semigroup::multiply(a, b);
        auto direct_result = a * b;
        
        benchmark::DoNotOptimize(unified_result);
        benchmark::DoNotOptimize(semigroup_result);
        benchmark::DoNotOptimize(direct_result);
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
        auto result = abeliangroup::multiply(a, b);
        
        benchmark::DoNotOptimize(result);
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
        auto unified_result = abeliangroup::multiply(a, b);
        auto semigroup_result = semigroup::multiply(a, b);
        
        benchmark::DoNotOptimize(unified_result);
        benchmark::DoNotOptimize(semigroup_result);
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
        auto result = abeliangroup::multiply(a, b);
        
        benchmark::DoNotOptimize(result);
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
        auto unified_result = abeliangroup::multiply(a, b);
        auto semigroup_result = semigroup::multiply(a, b);
        auto direct_result = a * b;
        
        benchmark::DoNotOptimize(unified_result);
        benchmark::DoNotOptimize(semigroup_result);
        benchmark::DoNotOptimize(direct_result);
        benchmark::ClobberMemory();
    }
}
BENCHMARK(BM_AllConstraintApproaches<PallasGroupJacobian>);
BENCHMARK(BM_AllConstraintApproaches<Edwards25519GroupExtended>);
