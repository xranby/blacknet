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
    
    std::size_t total_constraints = 0;
    std::size_t total_operations = 0;
    
    for (auto _ : state) {
        abeliangroup::MultilinearScalarMult<ECG, typename ECG::Scalar> mult;
        auto simple_constraints = mult.multiply_to_constraints(a, b);
        
        total_constraints += simple_constraints.size();
        
        // Count actual elliptic curve operations
        for (const auto& constraint : simple_constraints) {
            switch(constraint.type) {
                case abeliangroup::SimpleConstraint<ECG>::POINT_ADD:
                case abeliangroup::SimpleConstraint<ECG>::POINT_SUB:
                case abeliangroup::SimpleConstraint<ECG>::POINT_DOUBLE:
                    total_operations++;
                    break;
                default:
                    break;
            }
        }
        
        benchmark::DoNotOptimize(simple_constraints);
        benchmark::ClobberMemory();
    }
    
    state.counters["ConstraintsPerIter"] = benchmark::Counter(
        static_cast<double>(total_constraints) / state.iterations());
    state.counters["OperationsPerIter"] = benchmark::Counter(
        static_cast<double>(total_operations) / state.iterations());
}
BENCHMARK(BM_EllipticCurveMultilinearConstraints<PallasGroupJacobian>);
BENCHMARK(BM_EllipticCurveMultilinearConstraints<Edwards25519GroupExtended>);

template<typename ECG>
static void BM_EllipticCurveNeoConstraints(benchmark::State& state) {
    auto a = ECG::random(rng);
    auto b = ECG::Scalar::random(rng);
    
    std::size_t total_bit_constraints = 0;
    std::size_t total_field_constraints = 0;
    std::size_t total_goldilocks_constraints = 0;
    double total_commitment_cost = 0.0;
    
    for (auto _ : state) {
        abeliangroup::NeoOptimizedMult<ECG, typename ECG::Scalar, typename ECG::Base> neo_mult;
        auto bit_granular_cs = neo_mult.generate_constraint_system(a, b);
        
        total_bit_constraints += bit_granular_cs.bit_constraints.size();
        total_field_constraints += bit_granular_cs.field_constraints.size();
        total_goldilocks_constraints += bit_granular_cs.goldilocks_constraints.size();
        total_commitment_cost += bit_granular_cs.estimated_commitment_cost();
        
        benchmark::DoNotOptimize(bit_granular_cs.bit_constraints);
        benchmark::DoNotOptimize(bit_granular_cs.field_constraints);
        benchmark::DoNotOptimize(bit_granular_cs.goldilocks_constraints);
        benchmark::ClobberMemory();
    }
    
    state.counters["BitConstraintsPerIter"] = benchmark::Counter(
        static_cast<double>(total_bit_constraints) / state.iterations());
    state.counters["FieldConstraintsPerIter"] = benchmark::Counter(
        static_cast<double>(total_field_constraints) / state.iterations());
    state.counters["GoldilcksConstraintsPerIter"] = benchmark::Counter(
        static_cast<double>(total_goldilocks_constraints) / state.iterations());
    state.counters["EstimatedCommitmentCost"] = benchmark::Counter(
        total_commitment_cost / state.iterations());
    state.counters["TotalConstraintsPerIter"] = benchmark::Counter(
        static_cast<double>(total_bit_constraints + total_field_constraints + total_goldilocks_constraints) / state.iterations());
}
BENCHMARK(BM_EllipticCurveNeoConstraints<PallasGroupJacobian>);
BENCHMARK(BM_EllipticCurveNeoConstraints<Edwards25519GroupExtended>);

template<typename ECG>
static void BM_EllipticCurveStreamingConstraints(benchmark::State& state) {
    auto a = ECG::random(rng);
    auto b = ECG::Scalar::random(rng);
    
    std::size_t total_chunks = 0;
    std::size_t total_constraints = 0;
    std::size_t total_operations = 0;
    double total_matrix_efficiency = 0.0;
    double total_neo_commitment_cost = 0.0;
    
    for (auto _ : state) {
        abeliangroup::StreamingMultilinearMult<ECG, typename ECG::Scalar> streaming_mult;
        auto chunk_constraints = streaming_mult.process_in_chunks(a, b);
        
        total_chunks += chunk_constraints.size();
        
        // Count constraints across all chunks with Neo matrix metrics
        for (const auto& chunk : chunk_constraints) {
            total_constraints += chunk.constraints.size();
            total_matrix_efficiency += chunk.commitment_efficiency;
            total_neo_commitment_cost += chunk.neo_commitment_cost();
            
            // Count actual elliptic curve operations
            for (const auto& constraint : chunk.constraints) {
                switch(constraint.type) {
                    case abeliangroup::SimpleConstraint<ECG>::POINT_ADD:
                    case abeliangroup::SimpleConstraint<ECG>::POINT_SUB:
                    case abeliangroup::SimpleConstraint<ECG>::POINT_DOUBLE:
                        total_operations++;
                        break;
                    default:
                        break;
                }
            }
        }
        
        benchmark::DoNotOptimize(chunk_constraints);
        benchmark::ClobberMemory();
    }
    
    state.counters["ChunksPerIter"] = benchmark::Counter(
        static_cast<double>(total_chunks) / state.iterations());
    state.counters["ConstraintsPerIter"] = benchmark::Counter(
        static_cast<double>(total_constraints) / state.iterations());
    state.counters["OperationsPerIter"] = benchmark::Counter(
        static_cast<double>(total_operations) / state.iterations());
    state.counters["MatrixEfficiency"] = benchmark::Counter(
        total_matrix_efficiency / (state.iterations() * total_chunks / state.iterations()));
    state.counters["NeoCommitmentCost"] = benchmark::Counter(
        total_neo_commitment_cost / state.iterations());
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

// Comprehensive comparison of all constraint approaches
template<typename ECG>
static void BM_ConstraintApproachComparison(benchmark::State& state) {
    auto a = ECG::random(rng);
    auto b = ECG::Scalar::random(rng);
    
    for (auto _ : state) {
        state.PauseTiming();
        
        // Time Multilinear approach
        auto start_multi = std::chrono::high_resolution_clock::now();
        abeliangroup::MultilinearScalarMult<ECG, typename ECG::Scalar> mult;
        auto multi_constraints = mult.multiply_to_constraints(a, b);
        auto end_multi = std::chrono::high_resolution_clock::now();
        
        // Time Neo approach
        auto start_neo = std::chrono::high_resolution_clock::now();
        abeliangroup::NeoOptimizedMult<ECG, typename ECG::Scalar, typename ECG::Base> neo_mult;
        auto neo_cs = neo_mult.generate_constraint_system(a, b);
        auto end_neo = std::chrono::high_resolution_clock::now();
        
        // Time Streaming approach
        auto start_stream = std::chrono::high_resolution_clock::now();
        abeliangroup::StreamingMultilinearMult<ECG, typename ECG::Scalar> stream_mult;
        auto stream_chunks = stream_mult.process_in_chunks(a, b);
        auto end_stream = std::chrono::high_resolution_clock::now();
        
        state.ResumeTiming();
        
        // Calculate metrics
        auto multi_time = std::chrono::duration_cast<std::chrono::nanoseconds>(end_multi - start_multi).count();
        auto neo_time = std::chrono::duration_cast<std::chrono::nanoseconds>(end_neo - start_neo).count();
        auto stream_time = std::chrono::duration_cast<std::chrono::nanoseconds>(end_stream - start_stream).count();
        
        std::size_t stream_total_constraints = 0;
        for (const auto& chunk : stream_chunks) {
            stream_total_constraints += chunk.constraints.size();
        }
        
        std::size_t neo_total_constraints = neo_cs.bit_constraints.size() + 
                                           neo_cs.field_constraints.size() + 
                                           neo_cs.goldilocks_constraints.size();
        
        state.counters["MultilinearTimeNs"] = benchmark::Counter(multi_time);
        state.counters["NeoTimeNs"] = benchmark::Counter(neo_time);
        state.counters["StreamTimeNs"] = benchmark::Counter(stream_time);
        state.counters["MultilinearConstraints"] = benchmark::Counter(multi_constraints.size());
        state.counters["NeoConstraints"] = benchmark::Counter(neo_total_constraints);
        state.counters["StreamConstraints"] = benchmark::Counter(stream_total_constraints);
        state.counters["StreamChunks"] = benchmark::Counter(stream_chunks.size());
        state.counters["NeoSpeedup"] = benchmark::Counter(static_cast<double>(multi_time) / neo_time);
        state.counters["StreamSpeedup"] = benchmark::Counter(static_cast<double>(multi_time) / stream_time);
        
        benchmark::DoNotOptimize(multi_constraints);
        benchmark::DoNotOptimize(neo_cs);
        benchmark::DoNotOptimize(stream_chunks);
        benchmark::ClobberMemory();
    }
}
BENCHMARK(BM_ConstraintApproachComparison<PallasGroupJacobian>);
BENCHMARK(BM_ConstraintApproachComparison<Edwards25519GroupExtended>);
