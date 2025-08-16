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
        benchmark::DoNotOptimize(bit_granular_cs.small_field_constraints);
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

// Benchmark constraint generation vs direct computation
template<typename ECG>
static void BM_ConstraintVsDirectComparison(benchmark::State& state) {
    auto a = ECG::random(rng);
    auto b = ECG::Scalar::random(rng);
    
    for (auto _ : state) {
        state.PauseTiming();
        
        // Time constraint generation
        auto start_constraints = std::chrono::high_resolution_clock::now();
        abeliangroup::MultilinearScalarMult<ECG, typename ECG::Scalar> mult;
        auto constraints = mult.multiply_to_constraints(a, b);
        auto end_constraints = std::chrono::high_resolution_clock::now();
        
        // Time direct computation
        auto start_direct = std::chrono::high_resolution_clock::now();
        auto result = a * b;
        auto end_direct = std::chrono::high_resolution_clock::now();
        
        state.ResumeTiming();
        
        auto constraint_time = std::chrono::duration_cast<std::chrono::nanoseconds>(
            end_constraints - start_constraints).count();
        auto direct_time = std::chrono::duration_cast<std::chrono::nanoseconds>(
            end_direct - start_direct).count();
        
        state.counters["ConstraintTimeNs"] = benchmark::Counter(constraint_time);
        state.counters["DirectTimeNs"] = benchmark::Counter(direct_time);
        state.counters["ConstraintCount"] = benchmark::Counter(constraints.size());
        state.counters["Overhead"] = benchmark::Counter(
            static_cast<double>(constraint_time) / direct_time);
        
        benchmark::DoNotOptimize(constraints);
        benchmark::DoNotOptimize(result);
        benchmark::ClobberMemory();
    }
}
BENCHMARK(BM_ConstraintVsDirectComparison<PallasGroupJacobian>);
BENCHMARK(BM_ConstraintVsDirectComparison<Edwards25519GroupExtended>);
