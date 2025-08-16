/*
 * Copyright (c) 2025 Xerxes Rånby
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

#ifndef BLACKNET_CRYPTO_ADDSUBCHAIN_API_H
#define BLACKNET_CRYPTO_ADDSUBCHAIN_API_H

#include "abeliangroup.h"
#include <expected>
#include <chrono>
#include <memory>

namespace blacknet::crypto::addsubchain_api {

/*
 * Standardized API for ADDSUBCHAIN-E Operations
 * Provides consistent interfaces across all ADDSUBCHAIN-E functionality
 */

// Common result type for all ADDSUBCHAIN-E operations
template<typename T>
using Result = std::expected<T, std::error_code>;

// Standard performance metrics for all operations
struct PerformanceMetrics {
    std::chrono::nanoseconds computation_time;
    std::chrono::nanoseconds constraint_generation_time;
    std::size_t operation_count;
    std::size_t constraint_count;
    std::size_t memory_allocated_bytes;
    std::size_t memory_pool_utilization_percent;
    bool memory_pool_used;
};

// Standard operation result containing computation + constraints + metrics
template<typename ComputationResult, typename ConstraintType = abeliangroup::SimpleConstraint<ComputationResult>>
struct OperationResult {
    ComputationResult result;
    std::vector<ConstraintType> constraints;
    PerformanceMetrics metrics;
    bool constant_time_safe;
    
    // Convenience methods for result validation
    bool has_constraints() const { return !constraints.empty(); }
    bool is_secure() const { return constant_time_safe; }
    double constraint_overhead() const { 
        return metrics.constraint_generation_time.count() / 
               static_cast<double>(std::max(1L, metrics.computation_time.count()));
    }
};

// Standard configuration for all ADDSUBCHAIN-E operations
struct Configuration {
    bool enable_constant_time = false;
    bool enable_constraint_generation = true;
    bool enable_performance_metrics = false;
    std::size_t memory_pool_size = 1024 * 1024; // 1MB default
    std::size_t max_scalar_bits = 256;
    
    // Validation
    Result<void> validate() const {
        if (max_scalar_bits > 1024) {
            return std::unexpected(abeliangroup::make_error_code(abeliangroup::Error::INVALID_BIT_LENGTH));
        }
        return {};
    }
};

// Unified API for scalar multiplication
template<typename AG, typename Scalar>
class ScalarMultiplication {
public:
    using ComputationResult = AG;
    using ConstraintType = abeliangroup::SimpleConstraint<AG>;
    using OpResult = OperationResult<ComputationResult, ConstraintType>;
    
    explicit ScalarMultiplication(const Configuration& config = {}) : config_(config) {
        if (auto validation = config_.validate(); !validation) {
            throw std::system_error(validation.error());
        }
        
        // Initialize memory pool if enabled
        if (config_.memory_pool_size > 0) {
            memory_pool_ = std::make_unique<abeliangroup::ConstraintMemoryPool<AG>>(config_.memory_pool_size);
        }
    }
    
    // Standard scalar multiplication API
    Result<OpResult> multiply(const AG& point, const Scalar& scalar) {
        auto start = std::chrono::high_resolution_clock::now();
        
        if (config_.enable_constant_time) {
            return multiply_constant_time(point, scalar, start);
        } else {
            return multiply_standard(point, scalar, start);
        }
    }
    
    // Batch operations with consistent API
    Result<std::vector<OpResult>> multiply_batch(
        const std::vector<AG>& points,
        const std::vector<Scalar>& scalars
    ) {
        if (points.size() != scalars.size()) {
            return std::unexpected(abeliangroup::make_error_code(abeliangroup::Error::CONSTRAINT_GENERATION_FAILED));
        }
        
        std::vector<OpResult> results;
        results.reserve(points.size());
        
        for (std::size_t i = 0; i < points.size(); ++i) {
            auto result = multiply(points[i], scalars[i]);
            if (!result) {
                return std::unexpected(result.error());
            }
            results.push_back(std::move(*result));
        }
        
        return results;
    }
    
    // Configuration management
    const Configuration& get_configuration() const { return config_; }
    void update_configuration(const Configuration& new_config) {
        if (auto validation = new_config.validate(); validation) {
            config_ = new_config;
            
            // Recreate memory pool if size changed
            if (config_.memory_pool_size != new_config.memory_pool_size && new_config.memory_pool_size > 0) {
                memory_pool_ = std::make_unique<abeliangroup::ConstraintMemoryPool<AG>>(new_config.memory_pool_size);
            } else if (new_config.memory_pool_size == 0) {
                memory_pool_.reset();
            }
        }
    }
    
    // Memory pool management
    void reset_memory_pool() {
        if (memory_pool_) {
            memory_pool_->reset();
        }
    }
    
    auto get_memory_stats() const -> std::optional<typename abeliangroup::ConstraintMemoryPool<AG>::MemoryStats> {
        if (memory_pool_) {
            return memory_pool_->get_stats();
        }
        return std::nullopt;
    }
    
private:
    Configuration config_;
    std::unique_ptr<abeliangroup::ConstraintMemoryPool<AG>> memory_pool_;
    
    Result<OpResult> multiply_standard(const AG& point, const Scalar& scalar, 
                                     std::chrono::high_resolution_clock::time_point start) {
        try {
            if (config_.enable_constraint_generation) {
                abeliangroup::UnifiedMultiplication<AG, Scalar> unified(memory_pool_.get());
                auto unified_result = unified.multiply_unified(point, scalar);
                
                auto end = std::chrono::high_resolution_clock::now();
                auto total_time = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
                
                return OpResult{
                    unified_result.result,
                    std::move(unified_result.constraints),
                    PerformanceMetrics{
                        total_time,
                        total_time / 4, // Estimated constraint generation time
                        unified_result.operation_count,
                        unified_result.constraint_count,
                        sizeof(abeliangroup::SimpleConstraint<AG>) * unified_result.constraint_count,
                        static_cast<std::size_t>(unified_result.memory_stats.utilization_ratio * 100),
                        memory_pool_ != nullptr
                    },
                    false // Not constant-time
                };
            } else {
                // Direct computation without constraints
                auto result = abeliangroup::SafeMultiplication<AG, Scalar>::multiply_safe(point, scalar);
                if (!result) {
                    return std::unexpected(result.error());
                }
                
                auto end = std::chrono::high_resolution_clock::now();
                auto total_time = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
                
                return OpResult{
                    *result,
                    {}, // No constraints
                    PerformanceMetrics{
                        total_time,
                        std::chrono::nanoseconds{0},
                        0, 0, 0, 0,
                        false // No memory pool used
                    },
                    false
                };
            }
        } catch (const std::bad_alloc&) {
            return std::unexpected(abeliangroup::make_error_code(abeliangroup::Error::MEMORY_ALLOCATION_FAILED));
        }
    }
    
    Result<OpResult> multiply_constant_time(const AG& point, const Scalar& scalar,
                                          std::chrono::high_resolution_clock::time_point start) {
        try {
            abeliangroup::UnifiedMultiplication<AG, Scalar> unified(memory_pool_.get());
            auto ct_result = unified.multiply_unified_constant_time(point, scalar);
            if (!ct_result) {
                return std::unexpected(ct_result.error());
            }
            
            auto end = std::chrono::high_resolution_clock::now();
            auto total_time = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
            
            return OpResult{
                ct_result->result,
                std::move(ct_result->constraints),
                PerformanceMetrics{
                    total_time,
                    total_time / 2, // CT overhead
                    ct_result->operation_count,
                    ct_result->constraint_count,
                    sizeof(abeliangroup::SimpleConstraint<AG>) * ct_result->constraint_count,
                    static_cast<std::size_t>(ct_result->memory_stats.utilization_ratio * 100),
                    memory_pool_ != nullptr
                },
                true // Constant-time safe
            };
        } catch (const std::bad_alloc&) {
            return std::unexpected(abeliangroup::make_error_code(abeliangroup::Error::MEMORY_ALLOCATION_FAILED));
        }
    }
};

// Unified API for commitment operations
template<typename G>
class CommitmentOperations {
public:
    using ComputationResult = G;
    using ConstraintType = std::vector<typename G::Base>; // Field constraints
    using OpResult = OperationResult<ComputationResult, ConstraintType>;
    
    explicit CommitmentOperations(const Configuration& config = {}) : config_(config) {}
    
    // Standard commitment opening API
    template<typename Field>
    Result<OpResult> generate_opening_proof(
        const PedersenCommitment<G>& commitment,
        const VectorDense<typename G::Scalar>& values
    ) {
        auto start = std::chrono::high_resolution_clock::now();
        
        try {
            auto commit_result = commitment.commit(values);
            auto constraints = commitment.template generate_opening_constraints<Field>(values);
            
            auto end = std::chrono::high_resolution_clock::now();
            auto total_time = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
            
            std::vector<ConstraintType> formatted_constraints;
            formatted_constraints.reserve(constraints.linear_constraints.size());
            for (const auto& constraint : constraints.linear_constraints) {
                formatted_constraints.push_back(constraint);
            }
            
            return OpResult{
                commit_result,
                std::move(formatted_constraints),
                PerformanceMetrics{
                    total_time,
                    total_time / 3,
                    values.size(),
                    constraints.linear_constraints.size() + constraints.quadratic_constraints.size(),
                    sizeof(Field) * constraints.linear_constraints.size()
                },
                config_.enable_constant_time
            };
        } catch (const std::bad_alloc&) {
            return std::unexpected(abeliangroup::make_error_code(abeliangroup::Error::MEMORY_ALLOCATION_FAILED));
        }
    }
    
private:
    Configuration config_;
};

// Factory for creating standardized ADDSUBCHAIN-E operations
class ADDSUBCHAINFactory {
public:
    template<typename AG, typename Scalar>
    static ScalarMultiplication<AG, Scalar> create_scalar_multiplication(
        const Configuration& config = {}
    ) {
        return ScalarMultiplication<AG, Scalar>(config);
    }
    
    template<typename G>
    static CommitmentOperations<G> create_commitment_operations(
        const Configuration& config = {}
    ) {
        return CommitmentOperations<G>(config);
    }
    
    // Standard configurations
    static Configuration secure_configuration() {
        return Configuration{
            .enable_constant_time = true,
            .enable_constraint_generation = true,
            .enable_performance_metrics = true,
            .memory_pool_size = 2 * 1024 * 1024, // 2MB
            .max_scalar_bits = 256
        };
    }
    
    static Configuration performance_configuration() {
        return Configuration{
            .enable_constant_time = false,
            .enable_constraint_generation = true,
            .enable_performance_metrics = true,
            .memory_pool_size = 4 * 1024 * 1024, // 4MB
            .max_scalar_bits = 512
        };
    }
    
    static Configuration minimal_configuration() {
        return Configuration{
            .enable_constant_time = false,
            .enable_constraint_generation = false,
            .enable_performance_metrics = false,
            .memory_pool_size = 512 * 1024, // 512KB
            .max_scalar_bits = 256
        };
    }
};

} // namespace blacknet::crypto::addsubchain_api

#endif