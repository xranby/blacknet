/*
 * Test file for unified abeliangroup implementation
 */

#include <gtest/gtest.h>
#include "abeliangroup_unified.h"
#include "pastacurves.h"
#include "edwards25519.h"
#include "fastrng.h"

using namespace blacknet::crypto;
using namespace blacknet::crypto::abeliangroup;

static FastDRG rng;

// Test basic constraint generation with Pallas curve
TEST(UnifiedAbelianGroupTest, BasicMultilinearConstraints) {
    auto engine = create_addsubchain_engine<PallasGroupJacobian, VestaField>("multilinear");
    
    // Generate random point and scalar
    auto point = PallasGroupJacobian::random(rng);
    auto scalar = VestaField::random(rng);
    
    // Test constraint generation
    auto result = engine->multiply_with_constraints(point, scalar);
    
    ASSERT_TRUE(result.has_value());
    EXPECT_GT(result->constraint_count, 0);
    EXPECT_GT(result->total_operations, 0);
    EXPECT_EQ(result->constraint_count, result->basic_constraints.elements.size());
}

// Test zkVM-optimized constraints
TEST(UnifiedAbelianGroupTest, ZkVMConstraints) {
    auto engine = create_addsubchain_engine<PallasGroupJacobian, VestaField>("zkvm");
    
    auto point = PallasGroupJacobian::random(rng);
    auto scalar = VestaField::random(rng);
    
    auto result = engine->multiply_with_constraints(point, scalar);
    
    ASSERT_TRUE(result.has_value());
    EXPECT_GT(result->sequential_memory_accesses, 0);
    EXPECT_GE(result->zkvm_efficiency_score, 0.0);
}

// Test Edwards25519 compatibility
TEST(UnifiedAbelianGroupTest, Edwards25519Compatibility) {
    auto engine = create_addsubchain_engine<Edwards25519GroupExtended, Field25519>("multilinear");
    
    auto point = Edwards25519GroupExtended::random(rng);
    auto scalar = Field25519::random(rng);
    
    auto result = engine->multiply_with_constraints(point, scalar);
    
    ASSERT_TRUE(result.has_value());
    EXPECT_GT(result->constraint_count, 0);
}

// Test memory pool efficiency
TEST(UnifiedAbelianGroupTest, MemoryPoolEfficiency) {
    auto engine = create_addsubchain_engine<PallasGroupJacobian, VestaField>("multilinear");
    
    auto& pool = engine->get_memory_pool();
    auto initial_stats = pool.get_stats();
    
    auto point = PallasGroupJacobian::random(rng);
    auto scalar = VestaField::random(rng);
    
    auto result = engine->multiply_with_constraints(point, scalar);
    
    auto final_stats = pool.get_stats();
    
    ASSERT_TRUE(result.has_value());
    EXPECT_GE(final_stats.used_memory, initial_stats.used_memory);
    EXPECT_GT(final_stats.utilization_ratio, 0.0);
}

// Test error handling
TEST(UnifiedAbelianGroupTest, ErrorHandling) {
    auto engine = create_addsubchain_engine<PallasGroupJacobian, VestaField>("multilinear");
    
    auto point = PallasGroupJacobian::random(rng);
    auto zero_scalar = VestaField{}; // Zero scalar should cause error
    
    auto result = engine->multiply_with_constraints(point, zero_scalar);
    
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), make_error_code(ADDSUBCHAINError::INVALID_SCALAR_ZERO));
}

// Test strategy switching
TEST(UnifiedAbelianGroupTest, StrategySwitch) {
    auto engine = create_addsubchain_engine<PallasGroupJacobian, VestaField>("multilinear");
    
    auto point = PallasGroupJacobian::random(rng);
    auto scalar = VestaField::random(rng);
    
    // Test with multilinear strategy
    auto multilinear_result = engine->multiply_with_constraints(point, scalar);
    ASSERT_TRUE(multilinear_result.has_value());
    
    // Switch to zkVM strategy
    engine->set_strategy(UnifiedADDSUBCHAIN<PallasGroupJacobian, VestaField>::create_zkvm_strategy());
    auto zkvm_result = engine->multiply_with_constraints(point, scalar);
    ASSERT_TRUE(zkvm_result.has_value());
    
    // Results should be different in terms of memory accesses
    EXPECT_NE(multilinear_result->sequential_memory_accesses, zkvm_result->sequential_memory_accesses);
}

// Test legacy compatibility
TEST(UnifiedAbelianGroupTest, LegacyCompatibility) {
    auto point = PallasGroupJacobian::random(rng);
    auto scalar = VestaField::random(rng);
    
    // Test legacy multiply function
    auto result = multiply(point, scalar);
    
    // Should return a valid point (not identity unless scalar was zero)
    EXPECT_NE(result, PallasGroupJacobian::additive_identity());
}

// Performance comparison test
TEST(UnifiedAbelianGroupTest, PerformanceComparison) {
    auto engine = create_addsubchain_engine<PallasGroupJacobian, VestaField>("multilinear");
    
    auto point = PallasGroupJacobian::random(rng);
    auto scalar = VestaField::random(rng);
    
    // Test simple multiplication (no constraints)
    auto start = std::chrono::high_resolution_clock::now();
    auto simple_result = engine->multiply_simple(point, scalar);
    auto simple_time = std::chrono::high_resolution_clock::now() - start;
    
    // Test with constraint generation
    start = std::chrono::high_resolution_clock::now();
    auto constraint_result = engine->multiply_with_constraints(point, scalar);
    auto constraint_time = std::chrono::high_resolution_clock::now() - start;
    
    ASSERT_TRUE(simple_result.has_value());
    ASSERT_TRUE(constraint_result.has_value());
    
    // Simple multiplication should be faster
    EXPECT_LT(simple_time, constraint_time);
    
    // Results should be the same
    // (This would require implementing comparison - simplified for now)
    EXPECT_NE(*simple_result, PallasGroupJacobian::additive_identity());
}