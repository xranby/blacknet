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

#ifndef BLACKNET_CRYPTO_MEMORY_POOL_USAGE_EXAMPLE_H
#define BLACKNET_CRYPTO_MEMORY_POOL_USAGE_EXAMPLE_H

#include "addsubchain_api.h"
#include "abeliangroup.h"
#include <chrono>
#include <iostream>

namespace blacknet::crypto {

/*
 * Usage Examples for Memory Pool Optimization in ADDSUBCHAIN-E
 * Demonstrates performance benefits of memory pooling for constraint generation
 */

class MemoryPoolUsageExamples {
public:
    // Example 1: Basic memory pooling usage
    static void example_basic_memory_pooling() {
        using namespace abeliangroup;
        using namespace addsubchain_api;
        
        // Create configuration with memory pooling enabled
        auto config = ADDSUBCHAINFactory::performance_configuration();
        
        // Create scalar multiplication with memory pooling
        ScalarMultiplication<TestGroup, TestScalar> scalar_mult(config);
        
        TestGroup point = TestGroup::generator();
        TestScalar scalar(12345);
        
        // Perform multiplication with automatic memory pooling
        auto result = scalar_mult.multiply(point, scalar);
        
        if (result) {
            std::cout << "Scalar multiplication completed with:\n";
            std::cout << "- " << result->constraints.size() << " constraints generated\n";
            std::cout << "- Memory pool utilization: " 
                      << result->metrics.memory_pool_utilization_percent << "%\n";
            std::cout << "- Memory pool used: " 
                      << (result->metrics.memory_pool_used ? "Yes" : "No") << "\n";
        }
    }
    
    // Example 2: Performance comparison with and without memory pooling
    static void example_performance_comparison() {
        using namespace abeliangroup;
        using namespace addsubchain_api;
        
        TestGroup point = TestGroup::generator();
        TestScalar scalar(999999); // Large scalar for significant constraint generation
        
        // Test without memory pooling
        Configuration no_pool_config = ADDSUBCHAINFactory::minimal_configuration();
        no_pool_config.memory_pool_size = 0; // Disable pooling
        
        ScalarMultiplication<TestGroup, TestScalar> no_pool_mult(no_pool_config);
        
        auto start = std::chrono::high_resolution_clock::now();
        auto result_no_pool = no_pool_mult.multiply(point, scalar);
        auto end = std::chrono::high_resolution_clock::now();
        auto no_pool_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        
        // Test with memory pooling
        Configuration pool_config = ADDSUBCHAINFactory::performance_configuration();
        pool_config.memory_pool_size = 4 * 1024 * 1024; // 4MB pool
        
        ScalarMultiplication<TestGroup, TestScalar> pool_mult(pool_config);
        
        start = std::chrono::high_resolution_clock::now();
        auto result_pool = pool_mult.multiply(point, scalar);
        end = std::chrono::high_resolution_clock::now();
        auto pool_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        
        // Compare results
        std::cout << "Performance Comparison:\n";
        std::cout << "Without memory pool: " << no_pool_time.count() << "μs\n";
        std::cout << "With memory pool: " << pool_time.count() << "μs\n";
        
        if (pool_time < no_pool_time) {
            double speedup = static_cast<double>(no_pool_time.count()) / pool_time.count();
            std::cout << "Speedup: " << speedup << "x faster with memory pooling\n";
        }
        
        if (result_pool) {
            std::cout << "Memory pool utilization: " 
                      << result_pool->metrics.memory_pool_utilization_percent << "%\n";
        }
    }
    
    // Example 3: Batch operations with memory pool reuse
    static void example_batch_operations() {
        using namespace abeliangroup;
        using namespace addsubchain_api;
        
        Configuration config = ADDSUBCHAINFactory::performance_configuration();
        ScalarMultiplication<TestGroup, TestScalar> scalar_mult(config);
        
        std::vector<TestGroup> points;
        std::vector<TestScalar> scalars;
        
        // Prepare batch of operations
        for (int i = 0; i < 100; ++i) {
            points.push_back(TestGroup::generator());
            scalars.push_back(TestScalar(i * 1000 + 12345));
        }
        
        std::cout << "Performing batch operations with memory pool reuse:\n";
        
        auto start = std::chrono::high_resolution_clock::now();
        auto batch_result = scalar_mult.multiply_batch(points, scalars);
        auto end = std::chrono::high_resolution_clock::now();
        
        auto batch_time = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        
        if (batch_result) {
            std::cout << "Batch of " << batch_result->size() << " operations completed\n";
            std::cout << "Total time: " << batch_time.count() << "ms\n";
            std::cout << "Average per operation: " 
                      << static_cast<double>(batch_time.count()) / batch_result->size() 
                      << "ms\n";
                      
            // Show memory stats from the last operation
            if (!batch_result->empty()) {
                auto stats = scalar_mult.get_memory_stats();
                if (stats) {
                    std::cout << "Final memory pool stats:\n";
                    std::cout << "- Total allocated: " << stats->total_allocated_bytes / 1024 << "KB\n";
                    std::cout << "- Current usage: " << stats->current_usage_bytes / 1024 << "KB\n";
                    std::cout << "- Utilization: " << (stats->utilization_ratio * 100) << "%\n";
                    std::cout << "- Pools created: " << stats->pools_count << "\n";
                }
            }
        }
        
        // Reset memory pool for next batch
        scalar_mult.reset_memory_pool();
        std::cout << "Memory pool reset for reuse\n";
    }
    
    // Example 4: Memory pool size tuning
    static void example_memory_pool_tuning() {
        using namespace abeliangroup;
        using namespace addsubchain_api;
        
        TestGroup point = TestGroup::generator();
        TestScalar scalar(123456789); // Large scalar
        
        std::vector<std::size_t> pool_sizes = {
            512 * 1024,   // 512KB
            1024 * 1024,  // 1MB
            2 * 1024 * 1024,  // 2MB
            4 * 1024 * 1024   // 4MB
        };
        
        std::cout << "Memory pool size tuning results:\n";
        
        for (auto pool_size : pool_sizes) {
            Configuration config = ADDSUBCHAINFactory::performance_configuration();
            config.memory_pool_size = pool_size;
            
            ScalarMultiplication<TestGroup, TestScalar> scalar_mult(config);
            
            auto start = std::chrono::high_resolution_clock::now();
            auto result = scalar_mult.multiply(point, scalar);
            auto end = std::chrono::high_resolution_clock::now();
            
            auto time = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
            
            std::cout << "Pool size " << (pool_size / 1024) << "KB: ";
            std::cout << time.count() << "μs";
            
            if (result) {
                std::cout << " (utilization: " 
                          << result->metrics.memory_pool_utilization_percent << "%)";
                          
                auto stats = scalar_mult.get_memory_stats();
                if (stats && stats->pools_count > 1) {
                    std::cout << " [" << stats->pools_count << " pools created]";
                }
            }
            std::cout << "\n";
        }
    }
    
    // Example 5: Direct memory pool usage (advanced)
    static void example_direct_memory_pool_usage() {
        using namespace abeliangroup;
        
        // Create memory pool directly
        ConstraintMemoryPool<TestGroup> memory_pool(1024 * 1024); // 1MB
        
        // Use with MultilinearScalarMult
        MultilinearScalarMult<TestGroup, TestScalar> mult(&memory_pool);
        
        TestGroup point = TestGroup::generator();
        TestScalar scalar(54321);
        
        auto constraints = mult.multiply_to_constraints(point, scalar);
        
        std::cout << "Direct memory pool usage:\n";
        std::cout << "Generated " << constraints.size() << " constraints\n";
        
        auto stats = memory_pool.get_stats();
        std::cout << "Memory pool stats:\n";
        std::cout << "- Total allocated: " << stats.total_allocated_bytes / 1024 << "KB\n";
        std::cout << "- Current usage: " << stats.current_usage_bytes / 1024 << "KB\n";
        std::cout << "- Utilization: " << (stats.utilization_ratio * 100) << "%\n";
        
        // Reset and reuse
        memory_pool.reset();
        std::cout << "Pool reset for reuse\n";
        
        // Use with UnifiedMultiplication  
        UnifiedMultiplication<TestGroup, TestScalar> unified(&memory_pool);
        auto unified_result = unified.multiply_unified(point, scalar);
        
        std::cout << "Unified multiplication with pool:\n";
        std::cout << "- Operations: " << unified_result.operation_count << "\n";
        std::cout << "- Constraints: " << unified_result.constraint_count << "\n";
        std::cout << "- Pool utilization: " 
                  << (unified_result.memory_stats.utilization_ratio * 100) << "%\n";
    }

private:
    // Placeholder types for examples - replace with actual types from your codebase
    struct TestGroup {
        static TestGroup generator() { return TestGroup{}; }
        TestGroup operator+(const TestGroup&) const { return *this; }
        TestGroup operator-(const TestGroup&) const { return *this; }
        TestGroup douple() const { return *this; }
        static TestGroup additive_identity() { return TestGroup{}; }
        bool is_identity() const { return false; }
        bool operator==(const TestGroup&) const = default;
    };
    
    struct TestScalar {
        explicit TestScalar(int val) : value(val) {}
        
        bool is_zero() const { return value == 0; }
        std::size_t bit_length() const { return 32; }
        bool get_bit(std::size_t pos) const { return (value >> pos) & 1; }
        
        auto bitsBegin() const { return BitIterator{value, 0}; }
        auto bitsEnd() const { return BitIterator{value, 32}; }
        
    private:
        int value;
        
        struct BitIterator {
            int val;
            std::size_t pos;
            
            bool operator*() const { return (val >> pos) & 1; }
            BitIterator& operator++() { ++pos; return *this; }
            bool operator!=(const BitIterator& other) const { return pos != other.pos; }
        };
    };
};

}

#endif