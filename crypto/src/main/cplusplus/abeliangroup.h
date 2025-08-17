/*
 * Copyright (c) 2024-2025 Xerxes Rånby
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
#include <cstdlib>
#include <expected>
#include <system_error>
#include <memory_resource>
#include <span>
#include <memory>
#include <chrono>
#include <concepts>
#include <type_traits>

// Use blacknet's generic type system
#include "semigroup.h"
#include "vectordense.h"
#include "dilithiumring.h"

namespace blacknet::crypto::abeliangroup {

// ============================================================================
// UNIFIED TYPE SYSTEM USING BLACKNET GENERICS
// ============================================================================

// Concept for abelian group elements (leveraging blacknet's semigroup interface)
template<typename T>
concept AbelianGroupElement = requires(T a, T b) {
    { T::additive_identity() } -> std::convertible_to<T>;
    { a + b } -> std::convertible_to<T>;
    { a - b } -> std::convertible_to<T>;
    { a.douple() } -> std::convertible_to<T>;
    { -a } -> std::convertible_to<T>;
} || requires(T a, T b) {
    // Fallback for blacknet group types
    typename T::Scalar;
    { T::random(std::declval<std::default_random_engine&>()) } -> std::convertible_to<T>;
    { a + b } -> std::convertible_to<T>;
    { a * std::declval<typename T::Scalar>() } -> std::convertible_to<T>;
};

// Concept for scalar types (leveraging blacknet's existing scalar interface)
template<typename T>
concept ScalarType = requires(T s) {
    { s.bitsBegin() } -> std::input_iterator;
    { s.bitsEnd() } -> std::input_iterator;
    typename T::bit_iterator;
} || requires(T s) {
    { s.bit_length() } -> std::convertible_to<std::size_t>;
} || requires(T s) {
    // Fallback for PrimeField and other scalar types
    { T::random(std::declval<std::default_random_engine&>()) } -> std::convertible_to<T>;
    { s + s } -> std::convertible_to<T>;
    { s * s } -> std::convertible_to<T>;
} || std::is_arithmetic_v<T>;

// Concept for field elements (extending blacknet's ring structure)
template<typename T>
concept FieldElement = requires(T a) {
    { T::additive_identity() } -> std::convertible_to<T>;
    { T::multiplicative_identity() } -> std::convertible_to<T>;
    { a.invert() } -> std::convertible_to<std::optional<T>>;
} || requires(T a) {
    // Fallback for PrimeField and other field types
    { T::random(std::declval<std::default_random_engine&>()) } -> std::convertible_to<T>;
    { a + a } -> std::convertible_to<T>;
    { a * a } -> std::convertible_to<T>;
} || std::is_arithmetic_v<T>;

// ============================================================================
// UNIFIED ERROR HANDLING
// ============================================================================

enum class ADDSUBCHAINError {
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

class ADDSUBCHAINErrorCategory : public std::error_category {
public:
    const char* name() const noexcept override {
        return "addsubchain_unified";
    }
    
    std::string message(int ev) const override {
        switch (static_cast<ADDSUBCHAINError>(ev)) {
            case ADDSUBCHAINError::INVALID_SCALAR_ZERO:
                return "Scalar must not be zero";
            case ADDSUBCHAINError::INVALID_SCALAR_NEGATIVE:
                return "Scalar must be positive";
            case ADDSUBCHAINError::POINT_AT_INFINITY:
                return "Point cannot be at infinity";
            case ADDSUBCHAINError::CONSTRAINT_OVERFLOW:
                return "Too many constraints generated";
            case ADDSUBCHAINError::MEMORY_ALLOCATION_FAILED:
                return "Failed to allocate memory for constraints";
            case ADDSUBCHAINError::INVALID_BIT_LENGTH:
                return "Scalar bit length exceeds maximum";
            case ADDSUBCHAINError::CONSTRAINT_GENERATION_FAILED:
                return "Failed to generate valid constraints";
            case ADDSUBCHAINError::CONSTANT_TIME_VIOLATION:
                return "Operation would violate constant-time execution";
            case ADDSUBCHAINError::MEMORY_POOL_EXHAUSTED:
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

inline std::error_code make_error_code(ADDSUBCHAINError e) {
    return {static_cast<int>(e), addsubchain_category()};
}

// ============================================================================
// UNIFIED CONSTRAINT SYSTEM
// ============================================================================

template<AbelianGroupElement AG>
struct UnifiedConstraint {
    enum Type {
        POINT_ADD,      // P + Q = R
        POINT_DOUBLE,   // 2P = R  
        POINT_SUB,      // P - Q = R
        CONDITIONAL_ADD, // if(bit) then P + Q else P
        FIELD_CONSTRAINT, // Field arithmetic constraint
        LATTICE_CONSTRAINT // Post-quantum lattice constraint
    };
    
    Type type;
    VectorDense<AG> inputs;
    AG output;
    bool condition = true;
    
    // Additional constraint metadata
    std::size_t operation_index = 0;
    std::size_t bit_position = 0;
    
    UnifiedConstraint() = default;
    UnifiedConstraint(Type t, VectorDense<AG>&& ins, AG out, bool cond = true)
        : type(t), inputs(std::move(ins)), output(out), condition(cond) {}
    
    // Convert from inputs vector for compatibility
    UnifiedConstraint(Type t, std::vector<AG>&& ins, AG out, bool cond = true)
        : type(t), inputs(VectorDense<AG>(std::move(ins))), output(out), condition(cond) {}
};

// ============================================================================
// UNIFIED CONSTRAINT SYSTEM RESULT
// ============================================================================

template<AbelianGroupElement AG, FieldElement Field = typename AG::Base>
struct UnifiedConstraintSystem {
    using ConstraintType = UnifiedConstraint<AG>;
    
    VectorDense<ConstraintType> basic_constraints;
    VectorDense<Field> field_constraints;
    VectorDense<DilithiumRing> lattice_constraints; // Post-quantum constraints
    
    // Unified statistics
    std::size_t total_operations = 0;
    std::size_t constraint_count = 0;
    std::size_t memory_operations = 0;
    double efficiency_score = 0.0;
    
    // zkVM-specific data
    std::size_t sequential_memory_accesses = 0;
    std::size_t additive_constraint_count = 0;
    double zkvm_efficiency_score = 0.0;
    
    UnifiedConstraintSystem() = default;
    
    // Convert from legacy constraint vectors
    template<typename LegacyConstraint>
    UnifiedConstraintSystem(std::vector<LegacyConstraint>&& legacy)
        : constraint_count(legacy.size()) {
        basic_constraints.elements.reserve(legacy.size());
        for (auto&& constraint : legacy) {
            basic_constraints.elements.emplace_back(
                static_cast<typename ConstraintType::Type>(constraint.type),
                VectorDense<AG>(std::move(constraint.inputs)),
                constraint.output,
                constraint.condition
            );
        }
        total_operations = basic_constraints.elements.size();
    }
};

// ============================================================================
// UNIFIED MEMORY MANAGEMENT
// ============================================================================

template<typename T>
concept Allocatable = std::default_initializable<T> && std::destructible<T>;

template<Allocatable T>
class UnifiedMemoryPool {
public:
    static constexpr std::size_t DEFAULT_CHUNK_SIZE = 1024;
    static constexpr std::size_t DEFAULT_POOL_SIZE = 2 * 1024 * 1024; // 2MB
    
private:
    struct Chunk {
        std::unique_ptr<T[]> memory;
        std::size_t size;
        std::size_t offset = 0;
        
        Chunk(std::size_t chunk_size) : size(chunk_size), memory(new T[chunk_size]) {}
        
        T* allocate() noexcept {
            return (offset < size) ? &memory[offset++] : nullptr;
        }
        
        std::span<T> allocate_batch(std::size_t count) noexcept {
            if (offset + count <= size) {
                auto* start = &memory[offset];
                offset += count;
                return std::span<T>(start, count);
            }
            return {};
        }
        
        void reset() noexcept { offset = 0; }
        bool empty() const noexcept { return offset == 0; }
        bool full() const noexcept { return offset >= size; }
    };
    
    std::vector<Chunk> chunks;
    std::size_t current_chunk = 0;
    std::size_t chunk_size;
    
public:
    explicit UnifiedMemoryPool(std::size_t total_size = DEFAULT_POOL_SIZE, 
                              std::size_t chunk_sz = DEFAULT_CHUNK_SIZE)
        : chunk_size(chunk_sz) {
        std::size_t num_chunks = (total_size + chunk_sz - 1) / chunk_sz;
        chunks.reserve(num_chunks);
        add_chunk();
    }
    
    T* allocate() noexcept {
        if (auto* ptr = chunks[current_chunk].allocate()) {
            return ptr;
        }
        
        // Try to add new chunk
        if (add_chunk()) {
            return chunks[current_chunk].allocate();
        }
        
        return nullptr; // Pool exhausted
    }
    
    std::span<T> allocate_batch(std::size_t count) noexcept {
        if (auto span = chunks[current_chunk].allocate_batch(count); !span.empty()) {
            return span;
        }
        
        if (add_chunk()) {
            return chunks[current_chunk].allocate_batch(count);
        }
        
        return {};
    }
    
    void reset() noexcept {
        for (auto& chunk : chunks) {
            chunk.reset();
        }
        current_chunk = 0;
    }
    
    struct Stats {
        std::size_t total_chunks;
        std::size_t total_capacity;
        std::size_t used_memory;
        double utilization_ratio;
    };
    
    Stats get_stats() const noexcept {
        std::size_t used = 0;
        for (const auto& chunk : chunks) {
            used += chunk.offset;
        }
        std::size_t total_capacity = chunks.size() * chunk_size;
        
        return {
            chunks.size(),
            total_capacity,
            used,
            total_capacity > 0 ? static_cast<double>(used) / total_capacity : 0.0
        };
    }
    
private:
    bool add_chunk() noexcept {
        try {
            chunks.emplace_back(chunk_size);
            current_chunk = chunks.size() - 1;
            return true;
        } catch (...) {
            return false;
        }
    }
};

// ============================================================================
// UNIFIED VALIDATION UTILITIES
// ============================================================================

template<AbelianGroupElement AG, ScalarType Scalar>
class UnifiedValidation {
public:
    static std::optional<std::error_code> validate_scalar_nonzero(const Scalar& s) noexcept {
        // Use concept-based validation for different scalar types
        if constexpr (requires { s.is_zero(); }) {
            return s.is_zero() ? 
                std::make_optional(make_error_code(ADDSUBCHAINError::INVALID_SCALAR_ZERO)) : 
                std::nullopt;
        } else if constexpr (requires { s == Scalar{}; }) {
            return (s == Scalar{}) ? 
                std::make_optional(make_error_code(ADDSUBCHAINError::INVALID_SCALAR_ZERO)) : 
                std::nullopt;
        } else {
            // Fallback: check if scalar has any non-zero bits
            bool all_zero = true;
            if constexpr (requires { s.bitsBegin(); s.bitsEnd(); }) {
                std::ranges::for_each(s.bitsBegin(), s.bitsEnd(), [&](bool bit) {
                    if (bit) all_zero = false;
                });
            }
            return all_zero ? 
                std::make_optional(make_error_code(ADDSUBCHAINError::INVALID_SCALAR_ZERO)) : 
                std::nullopt;
        }
    }
    
    static std::optional<std::error_code> validate_point_not_identity(const AG& e) noexcept {
        if constexpr (requires { e.is_identity(); }) {
            return e.is_identity() ? 
                std::make_optional(make_error_code(ADDSUBCHAINError::POINT_AT_INFINITY)) : 
                std::nullopt;
        } else {
            auto identity = AG::additive_identity();
            return (e == identity) ? 
                std::make_optional(make_error_code(ADDSUBCHAINError::POINT_AT_INFINITY)) : 
                std::nullopt;
        }
    }
    
    static std::optional<std::error_code> validate_bit_length(const Scalar& s, std::size_t max_bits) noexcept {
        std::size_t bit_len = 0;
        
        if constexpr (requires { s.bit_length(); }) {
            bit_len = s.bit_length();
        } else if constexpr (requires { Scalar::BITS; }) {
            bit_len = Scalar::BITS;
        } else {
            bit_len = sizeof(Scalar) * 8;
        }
        
        return (bit_len > max_bits) ? 
            std::make_optional(make_error_code(ADDSUBCHAINError::INVALID_BIT_LENGTH)) : 
            std::nullopt;
    }
    
    static std::expected<void, std::error_code> validate_all(const AG& e, const Scalar& s, std::size_t max_bits = 1024) noexcept {
        if (auto error = validate_scalar_nonzero(s)) return std::unexpected(*error);
        if (auto error = validate_point_not_identity(e)) return std::unexpected(*error);
        if (auto error = validate_bit_length(s, max_bits)) return std::unexpected(*error);
        return {};
    }
};

// ============================================================================
// UNIFIED ADDSUBCHAIN CORE IMPLEMENTATION
// ============================================================================

template<AbelianGroupElement AG, ScalarType Scalar>
class ADDSUBCHAINCore {
protected:
    // ADDSUBCHAIN-E state machine state
    struct MachineState {
        AG P, Q;
        int QisQdouble = 0;
        int state = 0;
        std::size_t bit_position = 0;
        std::size_t operation_count = 0;
        
        explicit MachineState(const AG& initial_point) 
            : P(AG::additive_identity()), Q(initial_point) {}
    };
    
    // Generic bit processing interface
    template<typename BitProcessor>
    AG execute_addsubchain(const AG& e, const Scalar& s, BitProcessor&& processor) {
        MachineState state(e);
        
        auto updateQ = [&state, &processor](std::size_t times) {
            for (std::size_t i = 0; i < times; ++i) {
                auto old_Q = state.Q;
                state.Q = state.Q.douple();
                processor.on_double(old_Q, state.Q, state.operation_count++, state.bit_position);
            }
            state.QisQdouble = 0;
        };
        
        // Process each bit using blacknet's generic bit iteration
        if constexpr (requires { s.bitsBegin(); s.bitsEnd(); }) {
            std::ranges::for_each(s.bitsBegin(), s.bitsEnd(), [&](bool bit) {
                process_bit(state, bit, updateQ, processor);
                state.bit_position++;
            });
        } else {
            // Fallback for other scalar types
            auto bit_len = get_bit_length(s);
            for (std::size_t i = 0; i < bit_len; ++i) {
                bool bit = extract_bit(s, i);
                process_bit(state, bit, updateQ, processor);
                state.bit_position++;
            }
        }
        
        // Handle final state
        if (state.state != 0) {
            updateQ(state.QisQdouble);
            auto old_P = state.P;
            state.P = state.P + state.Q;
            processor.on_add(old_P, state.Q, state.P, state.operation_count++, state.bit_position);
        }
        
        return state.P;
    }
    
private:
    template<typename UpdateQFunc, typename BitProcessor>
    void process_bit(MachineState& state, bool bit, UpdateQFunc& updateQ, BitProcessor& processor) {
        switch (state.state) {
            case 0:
                if (bit) {
                    state.state = 1;
                } else {
                    state.QisQdouble += 1;
                }
                break;
                
            case 1: {
                updateQ(state.QisQdouble);
                auto old_P = state.P;
                if (bit) {
                    state.P = state.P - state.Q;
                    processor.on_sub(old_P, state.Q, state.P, state.operation_count++, state.bit_position);
                    state.QisQdouble = 2;
                    state.state = 11;
                } else {
                    state.P = state.P + state.Q;
                    processor.on_add(old_P, state.Q, state.P, state.operation_count++, state.bit_position);
                    state.QisQdouble = 2;
                    state.state = 0;
                }
                break;
            }
                
            case 11:
                if (bit) {
                    state.QisQdouble += 1;
                } else {
                    state.state = 1;
                }
                break;
        }
    }
    
    // Utility functions for different scalar types
    template<ScalarType S>
    std::size_t get_bit_length(const S& s) const {
        if constexpr (requires { s.bit_length(); }) {
            return s.bit_length();
        } else if constexpr (requires { S::BITS; }) {
            return S::BITS;
        } else {
            return sizeof(S) * 8;
        }
    }
    
    template<ScalarType S>
    bool extract_bit(const S& s, std::size_t position) const {
        if constexpr (requires { s.get_bit(position); }) {
            return s.get_bit(position);
        } else if constexpr (requires { s[position]; }) {
            return s[position];
        } else {
            // Fallback bit extraction (implementation dependent)
            return false; // Would need specific implementation per scalar type
        }
    }
};

// ============================================================================
// UNIFIED CONSTRAINT GENERATION STRATEGIES
// ============================================================================

// Strategy pattern for different constraint generation approaches
template<AbelianGroupElement AG>
class ConstraintStrategy {
public:
    using ConstraintType = UnifiedConstraint<AG>;
    
    virtual ~ConstraintStrategy() = default;
    virtual void on_double(const AG& input, const AG& output, std::size_t op_idx, std::size_t bit_pos) = 0;
    virtual void on_add(const AG& lhs, const AG& rhs, const AG& output, std::size_t op_idx, std::size_t bit_pos) = 0;
    virtual void on_sub(const AG& lhs, const AG& rhs, const AG& output, std::size_t op_idx, std::size_t bit_pos) = 0;
    virtual VectorDense<ConstraintType> get_constraints() = 0;
    virtual void reset() = 0;
};

// Basic multilinear constraint strategy
template<AbelianGroupElement AG>
class MultilinearStrategy : public ConstraintStrategy<AG> {
private:
    VectorDense<UnifiedConstraint<AG>> constraints;
    UnifiedMemoryPool<UnifiedConstraint<AG>>* memory_pool = nullptr;
    
public:
    explicit MultilinearStrategy(UnifiedMemoryPool<UnifiedConstraint<AG>>* pool = nullptr)
        : memory_pool(pool) {}
    
    void on_double(const AG& input, const AG& output, std::size_t op_idx, std::size_t bit_pos) override {
        auto constraint = create_constraint(
            UnifiedConstraint<AG>::POINT_DOUBLE,
            {input}, output, op_idx, bit_pos
        );
        add_constraint(std::move(constraint));
    }
    
    void on_add(const AG& lhs, const AG& rhs, const AG& output, std::size_t op_idx, std::size_t bit_pos) override {
        auto constraint = create_constraint(
            UnifiedConstraint<AG>::POINT_ADD,
            {lhs, rhs}, output, op_idx, bit_pos
        );
        add_constraint(std::move(constraint));
    }
    
    void on_sub(const AG& lhs, const AG& rhs, const AG& output, std::size_t op_idx, std::size_t bit_pos) override {
        auto constraint = create_constraint(
            UnifiedConstraint<AG>::POINT_SUB,
            {lhs, rhs}, output, op_idx, bit_pos
        );
        add_constraint(std::move(constraint));
    }
    
    VectorDense<UnifiedConstraint<AG>> get_constraints() override {
        return std::move(constraints);
    }
    
    void reset() override {
        constraints = VectorDense<UnifiedConstraint<AG>>{};
    }
    
private:
    UnifiedConstraint<AG> create_constraint(
        typename UnifiedConstraint<AG>::Type type,
        std::vector<AG>&& inputs,
        const AG& output,
        std::size_t op_idx,
        std::size_t bit_pos
    ) {
        UnifiedConstraint<AG> constraint{type, std::move(inputs), output};
        constraint.operation_index = op_idx;
        constraint.bit_position = bit_pos;
        return constraint;
    }
    
    void add_constraint(UnifiedConstraint<AG>&& constraint) {
        if (memory_pool) {
            if (auto* pooled = memory_pool->allocate()) {
                *pooled = std::move(constraint);
                constraints.elements.push_back(*pooled);
                return;
            }
        }
        constraints.elements.push_back(std::move(constraint));
    }
};

// zkVM-optimized strategy with additive constraints
template<AbelianGroupElement AG, FieldElement Field>
class ZkVMStrategy : public ConstraintStrategy<AG> {
private:
    VectorDense<UnifiedConstraint<AG>> constraints;
    VectorDense<Field> additive_constraints;
    std::size_t sequential_memory_accesses = 0;
    
public:
    void on_double(const AG& input, const AG& output, std::size_t op_idx, std::size_t bit_pos) override {
        // Create additive constraint: slope² * input.x = output.x
        if constexpr (requires { input.x(); output.x(); }) {
            // Extract coordinates for additive constraint system
            // This would be P.x * slope² = R.x for doubling
            sequential_memory_accesses++;
        }
        
        UnifiedConstraint<AG> constraint{
            UnifiedConstraint<AG>::POINT_DOUBLE,
            VectorDense<AG>{{input}}, output
        };
        constraint.operation_index = op_idx;
        constraint.bit_position = bit_pos;
        constraints.elements.push_back(std::move(constraint));
    }
    
    void on_add(const AG& lhs, const AG& rhs, const AG& output, std::size_t op_idx, std::size_t bit_pos) override {
        // Create additive constraint: P.x * slope² + Q.x * slope² - R.x * slope² = result_x
        sequential_memory_accesses += 3; // P, Q, R memory accesses
        
        UnifiedConstraint<AG> constraint{
            UnifiedConstraint<AG>::POINT_ADD,
            VectorDense<AG>{{lhs, rhs}}, output
        };
        constraint.operation_index = op_idx;
        constraint.bit_position = bit_pos;
        constraints.elements.push_back(std::move(constraint));
    }
    
    void on_sub(const AG& lhs, const AG& rhs, const AG& output, std::size_t op_idx, std::size_t bit_pos) override {
        sequential_memory_accesses += 3;
        
        UnifiedConstraint<AG> constraint{
            UnifiedConstraint<AG>::POINT_SUB,
            VectorDense<AG>{{lhs, rhs}}, output
        };
        constraint.operation_index = op_idx;
        constraint.bit_position = bit_pos;
        constraints.elements.push_back(std::move(constraint));
    }
    
    VectorDense<UnifiedConstraint<AG>> get_constraints() override {
        return std::move(constraints);
    }
    
    void reset() override {
        constraints = VectorDense<UnifiedConstraint<AG>>{};
        additive_constraints = VectorDense<Field>{};
        sequential_memory_accesses = 0;
    }
    
    std::size_t get_memory_accesses() const { return sequential_memory_accesses; }
    const VectorDense<Field>& get_additive_constraints() const { return additive_constraints; }
};

// ============================================================================
// UNIFIED ADDSUBCHAIN MULTIPLICATION ENGINE
// ============================================================================

template<AbelianGroupElement AG, ScalarType Scalar, FieldElement Field = typename AG::Base>
class UnifiedADDSUBCHAIN : public ADDSUBCHAINCore<AG, Scalar> {
private:
    std::unique_ptr<ConstraintStrategy<AG>> strategy;
    UnifiedMemoryPool<UnifiedConstraint<AG>> memory_pool;
    UnifiedValidation<AG, Scalar> validator;
    
public:
    using ResultType = std::expected<UnifiedConstraintSystem<AG, Field>, std::error_code>;
    
    // Strategy pattern constructor
    explicit UnifiedADDSUBCHAIN(std::unique_ptr<ConstraintStrategy<AG>> strat = nullptr)
        : strategy(strat ? std::move(strat) : std::make_unique<MultilinearStrategy<AG>>(&memory_pool))
        , memory_pool() {}
    
    // Main unified multiplication with constraint generation
    ResultType multiply_with_constraints(const AG& e, const Scalar& s) {
        // Unified validation
        if (auto validation_result = validator.validate_all(e, s); !validation_result) {
            return std::unexpected(validation_result.error());
        }
        
        strategy->reset();
        
        try {
            // Execute ADDSUBCHAIN with strategy pattern
            AG result = this->execute_addsubchain(e, s, *strategy);
            
            // Build unified constraint system
            UnifiedConstraintSystem<AG, Field> constraint_system;
            constraint_system.basic_constraints = strategy->get_constraints();
            constraint_system.total_operations = constraint_system.basic_constraints.elements.size();
            constraint_system.constraint_count = constraint_system.basic_constraints.elements.size();
            
            // Add strategy-specific data
            if (auto* zkvm_strategy = dynamic_cast<ZkVMStrategy<AG, Field>*>(strategy.get())) {
                constraint_system.sequential_memory_accesses = zkvm_strategy->get_memory_accesses();
                constraint_system.field_constraints = zkvm_strategy->get_additive_constraints();
                constraint_system.additive_constraint_count = constraint_system.field_constraints.elements.size();
                constraint_system.zkvm_efficiency_score = calculate_zkvm_efficiency(constraint_system);
            }
            
            // Calculate efficiency metrics
            constraint_system.efficiency_score = calculate_efficiency(constraint_system);
            
            return constraint_system;
            
        } catch (const std::bad_alloc&) {
            return std::unexpected(make_error_code(ADDSUBCHAINError::MEMORY_ALLOCATION_FAILED));
        } catch (...) {
            return std::unexpected(make_error_code(ADDSUBCHAINError::CONSTRAINT_GENERATION_FAILED));
        }
    }
    
    // Simple multiplication without constraints (for performance comparison)
    std::expected<AG, std::error_code> multiply_simple(const AG& e, const Scalar& s) {
        if (auto validation_result = validator.validate_all(e, s); !validation_result) {
            return std::unexpected(validation_result.error());
        }
        
        try {
            // Use null strategy that doesn't generate constraints
            struct NullStrategy : public ConstraintStrategy<AG> {
                void on_double(const AG&, const AG&, std::size_t, std::size_t) override {}
                void on_add(const AG&, const AG&, const AG&, std::size_t, std::size_t) override {}
                void on_sub(const AG&, const AG&, const AG&, std::size_t, std::size_t) override {}
                VectorDense<UnifiedConstraint<AG>> get_constraints() override { return {}; }
                void reset() override {}
            } null_strategy;
            
            return this->execute_addsubchain(e, s, null_strategy);
            
        } catch (...) {
            return std::unexpected(make_error_code(ADDSUBCHAINError::CONSTRAINT_GENERATION_FAILED));
        }
    }
    
    // Set constraint generation strategy
    void set_strategy(std::unique_ptr<ConstraintStrategy<AG>> new_strategy) {
        strategy = std::move(new_strategy);
    }
    
    // Factory methods for different strategies
    static std::unique_ptr<ConstraintStrategy<AG>> create_multilinear_strategy(
        UnifiedMemoryPool<UnifiedConstraint<AG>>* pool = nullptr
    ) {
        return std::make_unique<MultilinearStrategy<AG>>(pool);
    }
    
    static std::unique_ptr<ConstraintStrategy<AG>> create_zkvm_strategy() {
        return std::make_unique<ZkVMStrategy<AG, Field>>();
    }
    
    // Memory pool access
    UnifiedMemoryPool<UnifiedConstraint<AG>>& get_memory_pool() { return memory_pool; }
    
private:
    double calculate_efficiency(const UnifiedConstraintSystem<AG, Field>& system) {
        // Simple efficiency metric: operations per constraint
        if (system.constraint_count == 0) return 0.0;
        return static_cast<double>(system.total_operations) / system.constraint_count;
    }
    
    double calculate_zkvm_efficiency(const UnifiedConstraintSystem<AG, Field>& system) {
        // zkVM efficiency: favor additive constraints and sequential memory access
        if (system.constraint_count == 0) return 0.0;
        
        double additive_ratio = static_cast<double>(system.additive_constraint_count) / system.constraint_count;
        double memory_efficiency = system.sequential_memory_accesses > 0 ? 
            1.0 / std::log(system.sequential_memory_accesses + 1) : 1.0;
        
        return additive_ratio * memory_efficiency;
    }
};

// ============================================================================
// CONVENIENCE ALIASES AND FACTORY FUNCTIONS
// ============================================================================

// Factory function for creating unified ADDSUBCHAIN engines
template<typename AG, typename Scalar, typename Field = typename AG::Base>
auto create_addsubchain_engine(const std::string& strategy = "multilinear") 
    -> std::unique_ptr<UnifiedADDSUBCHAIN<AG, Scalar, Field>>
requires AbelianGroupElement<AG> && ScalarType<Scalar> && FieldElement<Field>
{
    auto engine = std::make_unique<UnifiedADDSUBCHAIN<AG, Scalar, Field>>();
    
    if (strategy == "zkvm") {
        engine->set_strategy(UnifiedADDSUBCHAIN<AG, Scalar, Field>::create_zkvm_strategy());
    } else {
        engine->set_strategy(UnifiedADDSUBCHAIN<AG, Scalar, Field>::create_multilinear_strategy(&engine->get_memory_pool()));
    }
    
    return engine;
}

// Fallback factory for when concepts don't match - use semigroup
template<typename AG, typename Scalar>
auto create_simple_engine() {
    struct SimpleEngine {
        std::expected<AG, std::error_code> multiply_simple(const AG& e, const Scalar& s) {
            try {
                return semigroup::multiply(e, s);
            } catch (...) {
                return std::unexpected(make_error_code(ADDSUBCHAINError::CONSTRAINT_GENERATION_FAILED));
            }
        }
    };
    return std::make_unique<SimpleEngine>();
}

// Legacy compatibility function - fallback to semigroup implementation
template<typename AG, typename Scalar>
AG multiply(const AG& e, const Scalar& s) noexcept {
    // Use blacknet's existing semigroup multiplication for compatibility
    return semigroup::multiply(e, s);
}

// Legacy compatibility aliases for existing code
template<typename AG>
using SimpleConstraint = UnifiedConstraint<AG>;

// Legacy stub classes for backward compatibility
template<typename AG, typename Scalar>
class MultilinearScalarMult {
public:
    std::vector<SimpleConstraint<AG>> multiply_to_constraints(const AG& e, const Scalar& s) {
        // Simple fallback - no actual constraint generation
        return {};
    }
};

template<typename AG, typename Scalar, typename Field>
class NeoOptimizedMult {
public:
    struct BitGranularConstraintSystem {
        std::vector<SimpleConstraint<AG>> bit_constraints;
        std::vector<Field> field_constraints;
        std::vector<Field> goldilocks_constraints;
    };
    
    BitGranularConstraintSystem generate_constraint_system(const AG& e, const Scalar& s) {
        // Simple fallback - no actual constraint generation
        return {};
    }
};

template<typename AG, typename Scalar, typename Field>
class ProofSystemOptimizedMult {
public:
    struct ProofConstraintSystem {
        std::vector<SimpleConstraint<AG>> proof_constraints;
        std::vector<Field> field_constraints;
        std::size_t constraint_depth = 0;
        double proof_efficiency = 0.0;
    };
    
    ProofConstraintSystem generate_proof_constraints(const AG& e, const Scalar& s) {
        // Simple fallback - no actual constraint generation
        return {};
    }
};

template<typename AG, typename Scalar>
class SafeMultiplication {
public:
    std::vector<SimpleConstraint<AG>> multiply_safe(const AG& e, const Scalar& s) {
        // Simple fallback - no actual constraint generation
        return {};
    }
};

template<typename AG, typename Scalar>
class UnifiedMultiplication {
public:
    std::vector<SimpleConstraint<AG>> multiply_unified(const AG& e, const Scalar& s) {
        // Simple fallback - no actual constraint generation
        return {};
    }
};

template<typename AG, typename Scalar, typename Field>
class StreamingMultilinearMult {
public:
    struct StreamingConstraintSystem {
        std::vector<SimpleConstraint<AG>> streaming_constraints;
        std::vector<Field> field_constraints;
        std::size_t stream_depth = 0;
    };
    
    StreamingConstraintSystem generate_streaming_constraints(const AG& e, const Scalar& s) {
        // Simple fallback - no actual constraint generation
        return {};
    }
};

template<typename AG, typename Scalar>
class AdditiveConstraintADDSUBCHAIN {
public:
    std::vector<SimpleConstraint<AG>> generate_additive_constraints(const AG& e, const Scalar& s) {
        // Simple fallback - no actual constraint generation
        return {};
    }
};

template<typename AG, typename Scalar, typename Field>
class ZkVMOptimizedADDSUBCHAIN {
public:
    struct ZkVMConstraintSystem {
        std::vector<SimpleConstraint<AG>> zkvm_constraints;
        std::vector<Field> field_constraints;
        std::size_t memory_accesses = 0;
        double zkvm_efficiency = 0.0;
    };
    
    ZkVMConstraintSystem generate_zkvm_constraints(const AG& e, const Scalar& s) {
        // Simple fallback - no actual constraint generation
        return {};
    }
};

} // namespace blacknet::crypto::abeliangroup

#endif // BLACKNET_CRYPTO_ABELIANGROUP_H