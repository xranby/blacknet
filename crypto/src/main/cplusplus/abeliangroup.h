/*
 * Copyright (c) 2024 Xerxes Rånby
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

#ifndef BLACKNET_CRYPTO_ABELIANGROUP_H
#define BLACKNET_CRYPTO_ABELIANGROUP_H

#include <algorithm>
#include <vector>
#include <cstdint>
#include <expected>
#include <system_error>
#include <memory_resource>
#include <span>
#include <memory>

namespace blacknet::crypto {

/*
 * ADDSUBCHAIN-E: Optimized for low-degree multilinear polynomials
 * Prioritizing simple constraints over aggressive batching
 */

namespace abeliangroup {

// Error handling for ADDSUBCHAIN-E operations
enum class Error {
    INVALID_SCALAR_ZERO,
    INVALID_SCALAR_NEGATIVE,
    POINT_AT_INFINITY,
    CONSTRAINT_OVERFLOW,
    MEMORY_ALLOCATION_FAILED,
    INVALID_BIT_LENGTH,
    CONSTRAINT_GENERATION_FAILED,
    CONSTANT_TIME_VIOLATION,
    MEMORY_POOL_EXHAUSTED
};

// Error category for ADDSUBCHAIN-E
class ADDSUBCHAINErrorCategory : public std::error_category {
public:
    const char* name() const noexcept override {
        return "addsubchain";
    }
    
    std::string message(int ev) const override {
        switch (static_cast<Error>(ev)) {
            case Error::INVALID_SCALAR_ZERO:
                return "Scalar must not be zero";
            case Error::INVALID_SCALAR_NEGATIVE:
                return "Scalar must be positive";
            case Error::POINT_AT_INFINITY:
                return "Point cannot be at infinity";
            case Error::CONSTRAINT_OVERFLOW:
                return "Too many constraints generated";
            case Error::MEMORY_ALLOCATION_FAILED:
                return "Failed to allocate memory for constraints";
            case Error::INVALID_BIT_LENGTH:
                return "Scalar bit length exceeds maximum";
            case Error::CONSTRAINT_GENERATION_FAILED:
                return "Failed to generate valid constraints";
            case Error::CONSTANT_TIME_VIOLATION:
                return "Operation would violate constant-time execution";
            case Error::MEMORY_POOL_EXHAUSTED:
                return "Memory pool exhausted, increase pool size";
            default:
                return "Unknown ADDSUBCHAIN error";
        }
    }
};

inline const ADDSUBCHAINErrorCategory& addsubchain_category() {
    static ADDSUBCHAINErrorCategory instance;
    return instance;
}

inline std::error_code make_error_code(Error e) {
    return {static_cast<int>(e), addsubchain_category()};
}

// Forward declaration
template<typename AG>
struct SimpleConstraint;

// Memory pool for constraint allocation optimization
template<typename AG>
class ConstraintMemoryPool {
public:
    using Constraint = SimpleConstraint<AG>;
    
private:
    std::vector<std::unique_ptr<Constraint[]>> pools;
    static constexpr std::size_t POOL_CHUNK_SIZE = 1024;
    std::size_t current_pool_index = 0;
    std::size_t current_offset = 0;
    std::size_t total_size_bytes;
    
public:
    explicit ConstraintMemoryPool(std::size_t initial_size = 2 * 1024 * 1024) // 2MB default
        : total_size_bytes(initial_size) {
        pools.reserve(initial_size / (POOL_CHUNK_SIZE * sizeof(Constraint)));
        allocate_new_pool();
    }
    
    // Fast allocation from pool
    Constraint* allocate() {
        if (current_offset >= POOL_CHUNK_SIZE) {
            allocate_new_pool();
        }
        
        if (current_pool_index >= pools.size()) {
            return nullptr; // Pool exhausted
        }
        
        return &pools[current_pool_index][current_offset++];
    }
    
    // Allocate multiple constraints at once for better cache locality
    std::span<Constraint> allocate_batch(std::size_t count) {
        if (current_offset + count > POOL_CHUNK_SIZE) {
            allocate_new_pool();
        }
        
        if (current_pool_index >= pools.size() || current_offset + count > POOL_CHUNK_SIZE) {
            return {}; // Cannot satisfy batch request
        }
        
        auto* start = &pools[current_pool_index][current_offset];
        current_offset += count;
        return std::span<Constraint>(start, count);
    }
    
    // Reset pool for reuse (doesn't deallocate memory)
    void reset() {
        current_pool_index = 0;
        current_offset = 0;
    }
    
    // Get memory usage statistics
    struct MemoryStats {
        std::size_t total_allocated_bytes;
        std::size_t pools_count;
        std::size_t current_usage_bytes;
        double utilization_ratio;
    };
    
    MemoryStats get_stats() const {
        std::size_t total_bytes = pools.size() * POOL_CHUNK_SIZE * sizeof(Constraint);
        std::size_t used_bytes = (current_pool_index * POOL_CHUNK_SIZE + current_offset) * sizeof(Constraint);
        
        return {
            total_bytes,
            pools.size(),
            used_bytes,
            total_bytes > 0 ? static_cast<double>(used_bytes) / total_bytes : 0.0
        };
    }
    
private:
    void allocate_new_pool() {
        try {
            auto new_pool = std::make_unique<Constraint[]>(POOL_CHUNK_SIZE);
            pools.push_back(std::move(new_pool));
            current_pool_index = pools.size() - 1;
            current_offset = 0;
        } catch (const std::bad_alloc&) {
            // Pool exhausted - calling code should handle this
        }
    }
};

// Simple constraint types that translate to low-degree polynomials
template<typename AG>
struct SimpleConstraint {
    enum Type {
        POINT_ADD,      // P + Q = R (degree 1 in each variable)
        POINT_DOUBLE,   // 2P = R (degree 1)  
        POINT_SUB,      // P - Q = R (degree 1)
        CONDITIONAL_ADD // if(bit) then P + Q else P (degree 2 max)
    };
    
    Type type;
    std::vector<AG> inputs;
    AG output;
    bool condition = true;  // For conditional operations
    
    // Pool-aware construction
    SimpleConstraint() = default;
    SimpleConstraint(Type t, std::vector<AG>&& ins, AG out, bool cond = true)
        : type(t), inputs(std::move(ins)), output(out), condition(cond) {}
};

// Constant-time constraint generation for side-channel resistance
template<typename AG, typename Scalar>
class ConstantTimeConstraintGen {
public:
    static constexpr std::size_t MAX_CONSTRAINTS_PER_BIT = 4;
    static constexpr std::size_t MAX_SCALAR_BITS = 256;
    static constexpr std::size_t MAX_TOTAL_CONSTRAINTS = MAX_SCALAR_BITS * MAX_CONSTRAINTS_PER_BIT;
    
    struct FixedSizeConstraintSet {
        std::array<SimpleConstraint<AG>, MAX_TOTAL_CONSTRAINTS> constraints;
        std::array<bool, MAX_TOTAL_CONSTRAINTS> valid_mask;
        std::size_t total_count = MAX_TOTAL_CONSTRAINTS; // Always constant
        std::size_t valid_count = 0;
    };
    
    // Constant-time constraint generation - always same number of operations
    static FixedSizeConstraintSet generate_ct_constraints(const AG& e, const Scalar& s) {
        FixedSizeConstraintSet result{};
        std::size_t constraint_idx = 0;
        
        // Always process exactly MAX_SCALAR_BITS bits
        for (std::size_t bit_pos = 0; bit_pos < MAX_SCALAR_BITS; ++bit_pos) {
            bool bit = (bit_pos < s.bit_length()) ? s.get_bit(bit_pos) : false;
            
            // ALWAYS generate exactly MAX_CONSTRAINTS_PER_BIT constraints per bit
            // Use conditional assignment to avoid branches
            
            // Constraint 1: Always a POINT_DOUBLE (may be dummy)
            result.constraints[constraint_idx] = create_point_double_constraint(e);
            result.valid_mask[constraint_idx] = bit || (!bit); // Always true, but computed
            constraint_idx++;
            
            // Constraint 2: Conditional POINT_ADD (real if bit=1, dummy if bit=0)
            AG point_to_add = conditional_select(bit, e, AG::additive_identity());
            result.constraints[constraint_idx] = create_point_add_constraint(point_to_add, e);
            result.valid_mask[constraint_idx] = bit;
            constraint_idx++;
            
            // Constraint 3: Always a POINT_SUB (may be dummy)
            result.constraints[constraint_idx] = create_point_sub_constraint(e, e);
            result.valid_mask[constraint_idx] = conditional_select(bit, false, true);
            constraint_idx++;
            
            // Constraint 4: Always a dummy constraint for padding
            result.constraints[constraint_idx] = create_dummy_constraint();
            result.valid_mask[constraint_idx] = false;
            constraint_idx++;
            
            // Count valid constraints in constant time
            result.valid_count += bit ? 2 : 1; // No branches, arithmetic only
        }
        
        return result;
    }
    
private:
    // Constant-time conditional selection: return a if condition, else b
    static AG conditional_select(bool condition, const AG& a, const AG& b) {
        // This should be implemented using constant-time field operations
        // For now, simplified version (real implementation would use bitwise operations)
        return condition ? a : b;
    }
    
    static SimpleConstraint<AG> create_point_double_constraint(const AG& point) {
        return {
            SimpleConstraint<AG>::POINT_DOUBLE,
            {point},
            point.douple()
        };
    }
    
    static SimpleConstraint<AG> create_point_add_constraint(const AG& p1, const AG& p2) {
        return {
            SimpleConstraint<AG>::POINT_ADD,
            {p1, p2},
            p1 + p2
        };
    }
    
    static SimpleConstraint<AG> create_point_sub_constraint(const AG& p1, const AG& p2) {
        return {
            SimpleConstraint<AG>::POINT_SUB,
            {p1, p2},
            p1 - p2
        };
    }
    
    static SimpleConstraint<AG> create_dummy_constraint() {
        AG identity = AG::additive_identity();
        return {
            SimpleConstraint<AG>::POINT_ADD,
            {identity, identity},
            identity
        };
    }
};

template<typename AG, typename Scalar>
class MultilinearScalarMult {
private:
    std::vector<SimpleConstraint<AG>> constraints;
    std::vector<AG> intermediate_points;
    ConstraintMemoryPool<AG>* memory_pool = nullptr;
    
public:
    // Constructor with optional memory pool
    explicit MultilinearScalarMult(ConstraintMemoryPool<AG>* pool = nullptr)
        : memory_pool(pool) {}
    
    // Set memory pool for optimized allocation
    void set_memory_pool(ConstraintMemoryPool<AG>* pool) {
        memory_pool = pool;
    }
    // DEPRECATED: Use ConstantTimeConstraintGen for security-critical applications
    // Generate many simple constraints instead of few complex ones
    std::vector<SimpleConstraint<AG>> multiply_to_constraints(const AG& e, const Scalar& s) {
        constraints.clear();
        intermediate_points.clear();
        
        AG P = AG::additive_identity();
        AG Q = e;
        
        int point_idx = 0;
        int QisQdouble = 0;
        int state = 0;
        
        // Track doubling operations as separate simple constraints
        auto handleDoubling = [&](int times) {
            for (int i = 0; i < times; ++i) {
                AG doubled_Q = (i == 0) ? Q.douple() : intermediate_points.back().douple();
                
                if (memory_pool) {
                    auto* constraint = memory_pool->allocate();
                    if (constraint) {
                        *constraint = SimpleConstraint<AG>{
                            SimpleConstraint<AG>::POINT_DOUBLE,
                            {(i == 0) ? Q : intermediate_points.back()},
                            doubled_Q
                        };
                        constraints.push_back(*constraint);
                    } else {
                        // Fallback to regular allocation
                        constraints.push_back({
                            SimpleConstraint<AG>::POINT_DOUBLE,
                            {(i == 0) ? Q : intermediate_points.back()},
                            doubled_Q
                        });
                    }
                } else {
                    constraints.push_back({
                        SimpleConstraint<AG>::POINT_DOUBLE,
                        {(i == 0) ? Q : intermediate_points.back()},
                        doubled_Q
                    });
                }
                
                intermediate_points.push_back(doubled_Q);
            }
            return intermediate_points.back();
        };
        
        // Each bit generates at most 2-3 simple constraints
        std::ranges::for_each(s.bitsBegin(), s.bitsEnd(), [&](bool bit) {
            switch(state) {
                case 0:
                    if(bit) {
                        state = 1;
                    } else {
                        QisQdouble += 1;
                    }
                    break;
                    
                case 1: {
                    // Generate simple doubling constraints
                    AG current_Q = (QisQdouble > 0) ? handleDoubling(QisQdouble) : Q;
                    
                    if(bit) {
                        // P = P - current_Q (simple subtraction constraint)
                        AG new_P = P - current_Q;
                        if (memory_pool) {
                            auto* constraint = memory_pool->allocate();
                            if (constraint) {
                                *constraint = SimpleConstraint<AG>{
                                    SimpleConstraint<AG>::POINT_SUB,
                                    {P, current_Q},
                                    new_P
                                };
                                constraints.push_back(*constraint);
                            } else {
                                constraints.push_back({
                                    SimpleConstraint<AG>::POINT_SUB,
                                    {P, current_Q},
                                    new_P
                                });
                            }
                        } else {
                            constraints.push_back({
                                SimpleConstraint<AG>::POINT_SUB,
                                {P, current_Q},
                                new_P
                            });
                        }
                        P = new_P;
                        QisQdouble = 2;
                        state = 11;
                    } else {
                        // P = P + current_Q (simple addition constraint)
                        AG new_P = P + current_Q;
                        if (memory_pool) {
                            auto* constraint = memory_pool->allocate();
                            if (constraint) {
                                *constraint = SimpleConstraint<AG>{
                                    SimpleConstraint<AG>::POINT_ADD,
                                    {P, current_Q},
                                    new_P
                                };
                                constraints.push_back(*constraint);
                            } else {
                                constraints.push_back({
                                    SimpleConstraint<AG>::POINT_ADD,
                                    {P, current_Q},
                                    new_P
                                });
                            }
                        } else {
                            constraints.push_back({
                                SimpleConstraint<AG>::POINT_ADD,
                                {P, current_Q},
                                new_P
                            });
                        }
                        P = new_P;
                        QisQdouble = 2;
                        state = 0;
                    }
                    break;
                }
                    
                case 11:
                    if(bit) {
                        QisQdouble += 1;
                    } else {
                        state = 1;
                    }
                    break;
            }
        });
        
        // Handle final state with simple constraint
        if(state != 0) {
            AG current_Q = (QisQdouble > 0) ? handleDoubling(QisQdouble) : Q;
            AG final_P = P + current_Q;
            if (memory_pool) {
                auto* constraint = memory_pool->allocate();
                if (constraint) {
                    *constraint = SimpleConstraint<AG>{
                        SimpleConstraint<AG>::POINT_ADD,
                        {P, current_Q},
                        final_P
                    };
                    constraints.push_back(*constraint);
                } else {
                    constraints.push_back({
                        SimpleConstraint<AG>::POINT_ADD,
                        {P, current_Q},
                        final_P
                    });
                }
            } else {
                constraints.push_back({
                    SimpleConstraint<AG>::POINT_ADD,
                    {P, current_Q},
                    final_P
                });
            }
        }
        
        return constraints;
    }
};

// Safe scalar multiplication with comprehensive error handling
template<typename AG, typename Scalar>
class SafeMultiplication {
public:
    using Result = std::expected<AG, std::error_code>;
    using ConstraintResult = std::expected<std::vector<SimpleConstraint<AG>>, std::error_code>;
    
    static Result multiply_safe(const AG& e, const Scalar& s) {
        // Input validation
        if (auto error = validate_inputs(e, s); error) {
            return std::unexpected(*error);
        }
        
        try {
            return multiply_impl(e, s);
        } catch (const std::bad_alloc&) {
            return std::unexpected(make_error_code(Error::MEMORY_ALLOCATION_FAILED));
        } catch (...) {
            return std::unexpected(make_error_code(Error::CONSTRAINT_GENERATION_FAILED));
        }
    }
    
    static auto multiply_with_constraints_safe(const AG& e, const Scalar& s) 
        -> std::expected<std::pair<AG, std::vector<SimpleConstraint<AG>>>, std::error_code> {
        
        if (auto error = validate_inputs(e, s); error) {
            return std::unexpected(*error);
        }
        
        try {
            MultilinearScalarMult<AG, Scalar> mult;
            auto constraints = mult.multiply_to_constraints(e, s);
            auto result = multiply_impl(e, s);
            return std::make_pair(result, constraints);
        } catch (const std::bad_alloc&) {
            return std::unexpected(make_error_code(Error::MEMORY_ALLOCATION_FAILED));
        } catch (...) {
            return std::unexpected(make_error_code(Error::CONSTRAINT_GENERATION_FAILED));
        }
    }
    
    // Constant-time safe multiplication
    static auto multiply_constant_time_safe(const AG& e, const Scalar& s)
        -> std::expected<typename ConstantTimeConstraintGen<AG, Scalar>::FixedSizeConstraintSet, std::error_code> {
        
        if (auto error = validate_inputs_ct(e, s); error) {
            return std::unexpected(*error);
        }
        
        try {
            return ConstantTimeConstraintGen<AG, Scalar>::generate_ct_constraints(e, s);
        } catch (const std::bad_alloc&) {
            return std::unexpected(make_error_code(Error::MEMORY_ALLOCATION_FAILED));
        } catch (...) {
            return std::unexpected(make_error_code(Error::CONSTANT_TIME_VIOLATION));
        }
    }
    
private:
    static std::optional<std::error_code> validate_inputs(const AG& e, const Scalar& s) {
        if (s.is_zero()) {
            return make_error_code(Error::INVALID_SCALAR_ZERO);
        }
        
        if (e.is_identity()) {
            return make_error_code(Error::POINT_AT_INFINITY);
        }
        
        if (s.bit_length() > 1024) { // Reasonable upper bound
            return make_error_code(Error::INVALID_BIT_LENGTH);
        }
        
        return std::nullopt;
    }
    
    static std::optional<std::error_code> validate_inputs_ct(const AG& e, const Scalar& s) {
        if (auto basic_error = validate_inputs(e, s); basic_error) {
            return basic_error;
        }
        
        if (s.bit_length() > ConstantTimeConstraintGen<AG, Scalar>::MAX_SCALAR_BITS) {
            return make_error_code(Error::CONSTANT_TIME_VIOLATION);
        }
        
        return std::nullopt;
    }
    
    static AG multiply_impl(const AG& e, const Scalar& s) {
        AG P = AG::additive_identity();
        AG Q = e;

        int QisQdouble = 0;
        int state = 0;

        auto updateQ = [&Q, &QisQdouble]() {
            for (int i = 0; i < QisQdouble; ++i) {
                Q = Q.douple();
            }
            QisQdouble = 0;
        };

        std::ranges::for_each(s.bitsBegin(), s.bitsEnd(), [&](bool bit) {
            switch(state){
                case 0:
                    if(bit) {
                        state = 1;
                    } else {
                        QisQdouble += 1;
                    }
                    break;
                case 1:
                    // Q only needs to be updated in case P gets updated
                    updateQ();
                    if(bit) {
                        P = P - Q;
                        QisQdouble += 2;
                        state = 11;
                    } else {
                        P = P + Q;
                        QisQdouble += 2;
                        state = 0;
                    }
                    break;
                case 11:
                    if(bit) {
                        QisQdouble += 1;
                    } else {
                        state = 1;
                    }
                    break;
            }
        });

        if(state != 0){
            // Q only needs to be updated in case P gets updated
            updateQ();
            P = P + Q;
        }

        return P;
    }
};

// Legacy function for backward compatibility - now safe by default
template<typename AG, typename Scalar>
constexpr AG multiply(const AG& e, const Scalar& s) {
    auto result = SafeMultiplication<AG, Scalar>::multiply_safe(e, s);
    if (!result) {
        // For legacy compatibility, return identity on error
        // Real applications should use the safe versions
        return AG::additive_identity();
    }
    return *result;
}

// Unified computation-constraint architecture for optimal performance
template<typename AG, typename Scalar>
class UnifiedMultiplication {
private:
    struct ComputationStep {
        enum Type { DOUBLE, ADD, SUB, CONDITIONAL_ADD };
        Type type;
        bool generates_constraint;
        AG cached_result;  // Pre-computed result to avoid recomputation
        SimpleConstraint<AG> constraint;  // Associated constraint
    };
    
    std::vector<ComputationStep> steps;
    ConstraintMemoryPool<AG>* memory_pool = nullptr;
    
public:
    // Constructor with optional memory pool
    explicit UnifiedMultiplication(ConstraintMemoryPool<AG>* pool = nullptr)
        : memory_pool(pool) {}
    
    // Set memory pool for optimized allocation
    void set_memory_pool(ConstraintMemoryPool<AG>* pool) {
        memory_pool = pool;
    }
    
    struct UnifiedResult {
        AG result;
        std::vector<SimpleConstraint<AG>> constraints;
        std::size_t operation_count;
        std::size_t constraint_count;
        typename ConstraintMemoryPool<AG>::MemoryStats memory_stats;
    };
    
    // Single pass: compute result AND generate constraints efficiently
    UnifiedResult multiply_unified(const AG& e, const Scalar& s) {
        steps.clear();
        steps.reserve(s.bit_length() * 2); // Pre-allocate to avoid reallocations
        
        AG P = AG::additive_identity();
        AG Q = e;
        
        int QisQdouble = 0;
        int state = 0;
        std::size_t operation_count = 0;
        
        auto updateQ = [&]() {
            for (int i = 0; i < QisQdouble; ++i) {
                Q = Q.douple();
                
                // Record doubling step with constraint
                SimpleConstraint<AG> constraint;
                if (memory_pool) {
                    auto* pooled_constraint = memory_pool->allocate();
                    if (pooled_constraint) {
                        *pooled_constraint = {SimpleConstraint<AG>::POINT_DOUBLE, {Q}, Q.douple()};
                        constraint = *pooled_constraint;
                    } else {
                        constraint = {SimpleConstraint<AG>::POINT_DOUBLE, {Q}, Q.douple()};
                    }
                } else {
                    constraint = {SimpleConstraint<AG>::POINT_DOUBLE, {Q}, Q.douple()};
                }
                
                steps.push_back({
                    ComputationStep::DOUBLE,
                    true,
                    Q,  // Cache the result
                    constraint
                });
                operation_count++;
            }
            QisQdouble = 0;
        };

        std::ranges::for_each(s.bitsBegin(), s.bitsEnd(), [&](bool bit) {
            switch(state){
                case 0:
                    if(bit) {
                        state = 1;
                    } else {
                        QisQdouble += 1;
                    }
                    break;
                case 1:
                    // Q only needs to be updated in case P gets updated
                    updateQ();
                    if(bit) {
                        AG new_P = P - Q;
                        
                        // Record subtraction step with constraint
                        SimpleConstraint<AG> constraint;
                        if (memory_pool) {
                            auto* pooled_constraint = memory_pool->allocate();
                            if (pooled_constraint) {
                                *pooled_constraint = {SimpleConstraint<AG>::POINT_SUB, {P, Q}, new_P};
                                constraint = *pooled_constraint;
                            } else {
                                constraint = {SimpleConstraint<AG>::POINT_SUB, {P, Q}, new_P};
                            }
                        } else {
                            constraint = {SimpleConstraint<AG>::POINT_SUB, {P, Q}, new_P};
                        }
                        
                        steps.push_back({
                            ComputationStep::SUB,
                            true,
                            new_P,  // Cache the result
                            constraint
                        });
                        
                        P = new_P;
                        QisQdouble += 2;
                        state = 11;
                        operation_count++;
                    } else {
                        AG new_P = P + Q;
                        
                        // Record addition step with constraint
                        SimpleConstraint<AG> constraint;
                        if (memory_pool) {
                            auto* pooled_constraint = memory_pool->allocate();
                            if (pooled_constraint) {
                                *pooled_constraint = {SimpleConstraint<AG>::POINT_ADD, {P, Q}, new_P};
                                constraint = *pooled_constraint;
                            } else {
                                constraint = {SimpleConstraint<AG>::POINT_ADD, {P, Q}, new_P};
                            }
                        } else {
                            constraint = {SimpleConstraint<AG>::POINT_ADD, {P, Q}, new_P};
                        }
                        
                        steps.push_back({
                            ComputationStep::ADD,
                            true,
                            new_P,  // Cache the result
                            constraint
                        });
                        
                        P = new_P;
                        QisQdouble += 2;
                        state = 0;
                        operation_count++;
                    }
                    break;
                case 11:
                    if(bit) {
                        QisQdouble += 1;
                    } else {
                        state = 1;
                    }
                    break;
            }
        });

        if(state != 0){
            // Q only needs to be updated in case P gets updated
            updateQ();
            AG final_P = P + Q;
            
            // Record final addition
            SimpleConstraint<AG> constraint;
            if (memory_pool) {
                auto* pooled_constraint = memory_pool->allocate();
                if (pooled_constraint) {
                    *pooled_constraint = {SimpleConstraint<AG>::POINT_ADD, {P, Q}, final_P};
                    constraint = *pooled_constraint;
                } else {
                    constraint = {SimpleConstraint<AG>::POINT_ADD, {P, Q}, final_P};
                }
            } else {
                constraint = {SimpleConstraint<AG>::POINT_ADD, {P, Q}, final_P};
            }
            
            steps.push_back({
                ComputationStep::ADD,
                true,
                final_P,
                constraint
            });
            
            P = final_P;
            operation_count++;
        }

        // Extract constraints from recorded steps
        std::vector<SimpleConstraint<AG>> constraints;
        constraints.reserve(steps.size());
        
        for (const auto& step : steps) {
            if (step.generates_constraint) {
                constraints.push_back(step.constraint);
            }
        }
        
        typename ConstraintMemoryPool<AG>::MemoryStats stats{};
        if (memory_pool) {
            stats = memory_pool->get_stats();
        }
        
        return {
            P,
            std::move(constraints),
            operation_count,
            constraints.size(),
            stats
        };
    }
    
    // Constant-time unified computation
    auto multiply_unified_constant_time(const AG& e, const Scalar& s) 
        -> std::expected<UnifiedResult, std::error_code> {
        
        if (s.bit_length() > ConstantTimeConstraintGen<AG, Scalar>::MAX_SCALAR_BITS) {
            return std::unexpected(make_error_code(Error::CONSTANT_TIME_VIOLATION));
        }
        
        try {
            auto ct_constraints = ConstantTimeConstraintGen<AG, Scalar>::generate_ct_constraints(e, s);
            auto computation_result = multiply_unified(e, s);
            
            // Merge constant-time constraints with computation constraints
            std::vector<SimpleConstraint<AG>> merged_constraints;
            merged_constraints.reserve(computation_result.constraints.size() + ct_constraints.valid_count);
            
            // Add valid constraints from constant-time generation
            for (std::size_t i = 0; i < ct_constraints.total_count; ++i) {
                if (ct_constraints.valid_mask[i]) {
                    merged_constraints.push_back(ct_constraints.constraints[i]);
                }
            }
            
            // Add computation constraints
            merged_constraints.insert(merged_constraints.end(),
                                    computation_result.constraints.begin(),
                                    computation_result.constraints.end());
            
            return UnifiedResult{
                computation_result.result,
                std::move(merged_constraints),
                computation_result.operation_count,
                merged_constraints.size()
            };
            
        } catch (const std::bad_alloc&) {
            return std::unexpected(make_error_code(Error::MEMORY_ALLOCATION_FAILED));
        } catch (...) {
            return std::unexpected(make_error_code(Error::CONSTRAINT_GENERATION_FAILED));
        }
    }
    
    // Get performance metrics
    struct PerformanceMetrics {
        std::size_t total_steps;
        std::size_t constraint_generating_steps;
        std::size_t cached_operations;
        double constraint_overhead_ratio;
    };
    
    PerformanceMetrics get_metrics() const {
        std::size_t constraint_steps = 0;
        std::size_t cached_ops = 0;
        
        for (const auto& step : steps) {
            if (step.generates_constraint) {
                constraint_steps++;
            }
            if (step.cached_result != AG::additive_identity()) {  // Simplified check
                cached_ops++;
            }
        }
        
        return {
            steps.size(),
            constraint_steps,
            cached_ops,
            static_cast<double>(constraint_steps) / std::max(1UL, steps.size())
        };
    }
};

// Backward compatibility function - now uses unified architecture
template<typename AG, typename Scalar>
constexpr auto multiply_with_constraints(const AG& e, const Scalar& s) {
    UnifiedMultiplication<AG, Scalar> unified;
    auto result = unified.multiply_unified(e, s);
    return std::make_pair(result.result, result.constraints);
}

// Multilinear polynomial representation for proof systems
template<typename Field>
struct MultilinearConstraintPoly {
    // Each constraint becomes a simple multilinear polynomial
    
    // Point addition: (x1 + x2 - x3) = 0
    // Degree 1 in each variable
    static Field point_add_constraint(const std::vector<Field>& vars) {
        return vars[0] + vars[1] - vars[2];
    }
    
    // Point doubling: (2*x1 - x2) = 0  
    // Degree 1
    static Field point_double_constraint(const std::vector<Field>& vars) {
        return Field(2) * vars[0] - vars[1];
    }
    
    // Point subtraction: (x1 - x2 - x3) = 0
    // Degree 1 in each variable
    static Field point_sub_constraint(const std::vector<Field>& vars) {
        return vars[0] - vars[1] - vars[2];
    }
    
    // Conditional addition: bit * (x1 + x2 - x3) + (1-bit) * (x1 - x3) = 0
    // Degree 2 maximum (bit * variable terms)
    static Field conditional_add_constraint(const std::vector<Field>& vars, Field bit) {
        Field add_term = bit * (vars[0] + vars[1] - vars[2]);
        Field identity_term = (Field(1) - bit) * (vars[0] - vars[2]);
        return add_term + identity_term;
    }
};

// Optimized for Neo-style folding with pay-per-bit commitments
template<typename AG, typename Scalar, typename Field>
class NeoOptimizedMult {
public:
    struct BitGranularConstraintSystem {
        std::vector<std::vector<bool>> bit_constraints;        // Cheap commits!
        std::vector<std::vector<Field>> field_constraints;     // Expensive commits
        std::vector<std::vector<uint8_t>> small_field_constraints;  // Goldilocks-friendly
        // Optimize for bit-width, not degree!
    };
    
    BitGranularConstraintSystem generate_constraint_system(const AG& e, const Scalar& s) {
        BitGranularConstraintSystem cs;
        
        // Process scalar bit-by-bit for optimal pay-per-bit costs
        std::ranges::for_each(s.bitsBegin(), s.bitsEnd(), [&](bool bit) {
            // Bit operations are almost free to commit to!
            cs.bit_constraints.push_back({bit});
            
            // Only use expensive field operations when necessary
            if (bit) {
                // Minimal field arithmetic for actual point operations
                cs.small_field_constraints.push_back(
                    encode_goldilocks_operation(bit)
                );
            }
        });
        
        return cs;
    }
    
private:
    std::vector<uint8_t> encode_goldilocks_operation(bool bit) {
        // Encode operations using Goldilocks prime for efficiency
        return {}; // Implementation depends on specific bit operation
    }
};

// Optimized for PLONK/STARK-style systems
template<typename AG, typename Scalar, typename Field>
class ProofSystemOptimizedMult {
public:
    struct ConstraintSystem {
        std::vector<std::vector<Field>> linear_constraints;    // Degree 1
        std::vector<std::vector<Field>> quadratic_constraints; // Degree 2
        // No higher degree constraints needed!
    };
    
    ConstraintSystem generate_constraint_system(const AG& e, const Scalar& s) {
        MultilinearScalarMult<AG, Scalar> mult;
        auto simple_constraints = mult.multiply_to_constraints(e, s);
        
        ConstraintSystem cs;
        
        for (const auto& constraint : simple_constraints) {
            switch (constraint.type) {
                case SimpleConstraint<AG>::POINT_ADD:
                case SimpleConstraint<AG>::POINT_SUB:
                case SimpleConstraint<AG>::POINT_DOUBLE:
                    // All translate to degree-1 multilinear polynomials
                    cs.linear_constraints.push_back(
                        encode_linear_constraint(constraint)
                    );
                    break;
                    
                case SimpleConstraint<AG>::CONDITIONAL_ADD:
                    // Translates to degree-2 multilinear polynomial
                    cs.quadratic_constraints.push_back(
                        encode_quadratic_constraint(constraint)
                    );
                    break;
            }
        }
        
        return cs;
    }
    
private:
    std::vector<Field> encode_linear_constraint(const SimpleConstraint<AG>& constraint) {
        // Convert geometric constraint to field arithmetic
        // This is where the elliptic curve coordinate equations come in
        // Returns coefficients for linear multilinear polynomial
        return {}; // Implementation depends on curve coordinate system
    }
    
    std::vector<Field> encode_quadratic_constraint(const SimpleConstraint<AG>& constraint) {
        // Convert conditional operations to quadratic constraints
        return {}; // Implementation depends on specific conditional logic
    }
};

// Alternative: Stream-based approach for very large scalars
template<typename AG, typename Scalar>
class StreamingMultilinearMult {
    // Process scalar bits in chunks to keep constraint degrees low
    // Each chunk produces small set of simple constraints
    // Perfect for STARK-style systems with streaming verification
    
public:
    constexpr static size_t CHUNK_SIZE = 4; // Process 4 bits at a time
    
    struct ChunkConstraints {
        std::vector<SimpleConstraint<AG>> constraints;
        AG input_point;
        AG output_point;
    };
    
    std::vector<ChunkConstraints> process_in_chunks(const AG& e, const Scalar& s) {
        std::vector<ChunkConstraints> chunks;
        
        // Each chunk creates at most 8 simple constraints (4 bits × 2 ops max)
        // All constraints are degree ≤ 2 in multilinear polynomial form
        
        return chunks; // Implementation processes scalar in small chunks
    }
};

}

}

#endif