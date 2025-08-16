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

#ifndef BLACKNET_CRYPTO_ADDSUBCHAIN_INTEGRATION_EXAMPLE_H
#define BLACKNET_CRYPTO_ADDSUBCHAIN_INTEGRATION_EXAMPLE_H

#include "abeliangroup.h"
#include "r1cs.h"
#include "circuitbuilder.h"
#include "pedersencommitment.h"
#include "batchverification.h"
#include "pastacurves.h"
#include "edwards25519.h"

namespace blacknet::crypto {

/*
 * Integration Examples for ADDSUBCHAIN-E in Blacknet
 * Demonstrates how to leverage the new functionality
 */

class ADDSUBCHAINIntegrationExamples {
public:
    // Example 1: R1CS Integration for Zero-Knowledge Proofs
    static void example_r1cs_integration() {
        // Generate R1CS constraints for elliptic curve scalar multiplication
        PallasGroupJacobian base_point = PallasGroupJacobian::random(rng);
        VestaField scalar = VestaField::random(rng);
        
        // Create R1CS with ADDSUBCHAIN-E constraints
        auto r1cs = R1CS<PallasField>::elliptic_curve_scalar_mult_r1cs(
            base_point, scalar
        );
        
        // The R1CS can now be used with proof systems like Groth16, PLONK, etc.
        std::cout << "Generated R1CS with " << r1cs.constraints() 
                  << " constraints and " << r1cs.variables() << " variables\n";
    }
    
    // Example 2: Circuit Builder for Custom Constraint Systems  
    static void example_circuit_builder() {
        CircuitBuilder<PallasField, 2> builder;
        
        // Create circuit variables
        auto point_x = builder.input();
        auto point_y = builder.input(); 
        auto scalar_var = builder.input();
        
        // Generate elliptic curve scalar multiplication circuit using ADDSUBCHAIN-E
        PallasGroupJacobian base_point(PallasField(1), PallasField(2));
        VestaField scalar_value(42);
        
        auto [result_x, result_y] = builder.elliptic_curve_scalar_mult(
            point_x, point_y, scalar_var, base_point, scalar_value
        );
        
        // Convert to R1CS for use with proof systems
        auto r1cs = builder.r1cs();
        std::cout << "Circuit has " << r1cs.constraints() << " constraints\n";
    }
    
    // Example 3: Pedersen Commitment with Proof Support
    static void example_pedersen_commitments() {
        // Setup Pedersen commitment
        VectorDense<PallasGroupJacobian> pp = 
            PedersenCommitment<PallasGroupJacobian>::setup(sponge, 10);
        PedersenCommitment<PallasGroupJacobian> commitment(std::move(pp));
        
        // Create commitment values
        VectorDense<VestaField> values = VectorDense<VestaField>::random(rng, 10);
        auto commit_result = commitment.commit(values);
        
        // Generate constraints for zero-knowledge opening proofs
        auto constraints = commitment.generate_opening_constraints<PallasField>(values);
        std::cout << "Generated " << constraints.linear_constraints.size() 
                  << " linear and " << constraints.quadratic_constraints.size() 
                  << " quadratic constraints\n";
        
        // Neo-style optimization for pay-per-bit protocols
        auto neo_constraints = commitment.generate_neo_opening_constraints<PallasField>(values);
        std::cout << "Neo constraints: " << neo_constraints.bit_constraints.size() 
                  << " bit operations (low cost)\n";
    }
    
    // Example 4: Batch Signature Verification
    static void example_batch_verification() {
        // Create batch of signatures (simplified example)
        std::vector<BatchSignatureVerifier<PallasGroupJacobian, VestaField, PallasField>::Signature> signatures;
        
        for (int i = 0; i < 100; ++i) {
            signatures.push_back({
                PallasGroupJacobian::random(rng),  // public key
                VestaField::random(rng),           // signature r
                VestaField::random(rng),           // signature s  
                PallasField::random(rng)           // message hash
            });
        }
        
        // Batch verify with constraint generation
        auto result = BatchSignatureVerifier<PallasGroupJacobian, VestaField, PallasField>
            ::batch_verify(signatures);
        
        std::cout << "Batch verified " << result.signature_count 
                  << " signatures with " << result.constraints.size() 
                  << " ADDSUBCHAIN-E constraints\n";
        
        // Neo-optimized verification for better performance
        auto neo_result = BatchSignatureVerifier<PallasGroupJacobian, VestaField, PallasField>
            ::batch_verify_neo_optimized<PallasField>(signatures);
        
        std::cout << "Neo verification generated " << neo_result.bit_constraints.size()
                  << " bit constraints (efficient for lattice-based systems)\n";
    }
    
    // Example 5: Performance Comparison
    static void example_performance_comparison() {
        PallasGroupJacobian point = PallasGroupJacobian::random(rng);
        VestaField scalar = VestaField::random(rng);
        
        // Traditional scalar multiplication
        auto start = std::chrono::high_resolution_clock::now();
        auto result1 = point * scalar;
        auto end = std::chrono::high_resolution_clock::now();
        auto traditional_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        
        // ADDSUBCHAIN-E with constraint generation
        start = std::chrono::high_resolution_clock::now();
        auto [result2, constraints] = abeliangroup::multiply_with_constraints(point, scalar);
        end = std::chrono::high_resolution_clock::now();
        auto addsubchain_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        
        std::cout << "Traditional: " << traditional_time.count() << "μs\n";
        std::cout << "ADDSUBCHAIN-E: " << addsubchain_time.count() << "μs\n";
        std::cout << "Generated " << constraints.size() << " constraints\n";
        std::cout << "Results match: " << (result1 == result2 ? "Yes" : "No") << "\n";
    }
    
    // Example 6: Integration with Existing Blacknet Protocols
    static void example_blacknet_integration() {
        // Example of how ADDSUBCHAIN-E could enhance existing Blacknet features:
        
        // 1. Enhanced signature verification in transactions
        // Instead of individual Ed25519 verifications, use batch verification
        
        // 2. Zero-knowledge multi-signature proofs
        // Use R1CS constraints for privacy-preserving multi-sig verification
        
        // 3. Efficient commitment schemes for private transactions
        // Use Neo-optimized Pedersen commitments for better performance
        
        // 4. Proof-friendly HTLC operations
        // Generate constraints for hash time lock contracts with privacy
        
        std::cout << "ADDSUBCHAIN-E enables:\n";
        std::cout << "- Batch signature verification for blocks\n";
        std::cout << "- Zero-knowledge transaction privacy\n"; 
        std::cout << "- Efficient commitment schemes\n";
        std::cout << "- Proof-friendly smart contracts\n";
    }
    
private:
    static inline FastDRG rng;
    static inline SHA3<256> sponge;
};

}

#endif