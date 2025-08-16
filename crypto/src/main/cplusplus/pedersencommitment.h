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

#ifndef BLACKNET_CRYPTO_PEDERSENCOMMITMENT_H
#define BLACKNET_CRYPTO_PEDERSENCOMMITMENT_H

#include <oneapi/tbb/blocked_range.h>
#include <oneapi/tbb/parallel_reduce.h>

#include "vectordense.h"
#include "abeliangroup.h"
#include <cstdint>

namespace blacknet::crypto {

/*
 * Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing
 * Torben Pryds Pedersen
 * 1991
 * https://www.cs.cornell.edu/courses/cs754/2001fa/129.PDF
 */

template<typename G>
class PedersenCommitment {
    VectorDense<G> pp;
public:
    constexpr PedersenCommitment(const VectorDense<G>& pp) : pp(pp) {}
    constexpr PedersenCommitment(VectorDense<G>&& pp) : pp(std::move(pp)) {}

    template<typename Sponge>
    constexpr static VectorDense<G> setup(Sponge& sponge, std::size_t size) {
        return VectorDense<G>::squeeze(sponge, size);
    }

    constexpr G commit(const G::Scalar& s, const G::Scalar& t) const {
        return pp[0] * s + pp[1] * t;
    }

    constexpr bool open(const G& e, const G::Scalar& s, const G::Scalar& t) const {
        return e == commit(s, t);
    }

    constexpr G commit(const VectorDense<typename G::Scalar>& v) const {
        using namespace oneapi::tbb;
        return parallel_reduce(
            blocked_range<std::size_t>(0, v.size()),
            G::additive_identity(),
            [&](const blocked_range<std::size_t>& range, G acc) -> G {
                for (std::size_t i = range.begin(); i != range.end(); ++i)
                    acc += pp[i] * v[i];
                return acc;
            },
            [](const G& a, const G& b) -> G {
                return a + b;
            }
        );
    }

    constexpr bool open(const G& e, const VectorDense<typename G::Scalar>& v) const {
        return e == commit(v);
    }

    // Generate multilinear constraints for commitment opening proofs
    template<typename Field>
    struct CommitmentConstraints {
        std::vector<std::vector<Field>> linear_constraints;
        std::vector<std::vector<Field>> quadratic_constraints;
    };

    template<typename Field>
    constexpr CommitmentConstraints<Field> generate_opening_constraints(
        const VectorDense<typename G::Scalar>& values
    ) const {
        CommitmentConstraints<Field> constraints;
        
        // Generate constraints for each scalar multiplication pp[i] * v[i]
        for (std::size_t i = 0; i < values.size() && i < pp.size(); ++i) {
            abeliangroup::MultilinearScalarMult<G, typename G::Scalar> mult;
            auto simple_constraints = mult.multiply_to_constraints(pp[i], values[i]);
            
            // Convert SimpleConstraint to field constraints
            for (const auto& constraint : simple_constraints) {
                switch (constraint.type) {
                    case abeliangroup::SimpleConstraint<G>::POINT_ADD:
                    case abeliangroup::SimpleConstraint<G>::POINT_SUB:
                    case abeliangroup::SimpleConstraint<G>::POINT_DOUBLE:
                        // Add as linear constraint
                        constraints.linear_constraints.push_back(
                            encode_linear_commitment_constraint(constraint, i)
                        );
                        break;
                    case abeliangroup::SimpleConstraint<G>::CONDITIONAL_ADD:
                        // Add as quadratic constraint
                        constraints.quadratic_constraints.push_back(
                            encode_quadratic_commitment_constraint(constraint, i)
                        );
                        break;
                }
            }
        }
        
        return constraints;
    }

    // Optimized commitment with Neo-style pay-per-bit constraints
    template<typename Field>
    constexpr auto generate_neo_opening_constraints(
        const VectorDense<typename G::Scalar>& values
    ) const {
        abeliangroup::NeoOptimizedMult<G, typename G::Scalar, Field> neo_mult;
        
        struct NeoCommitmentConstraints {
            std::vector<std::vector<bool>> bit_constraints;
            std::vector<std::vector<Field>> field_constraints;
            std::vector<std::vector<uint8_t>> small_field_constraints;
        } neo_constraints;
        
        // Generate bit-granular constraints for each commitment component
        for (std::size_t i = 0; i < values.size() && i < pp.size(); ++i) {
            auto cs = neo_mult.generate_constraint_system(pp[i], values[i]);
            
            // Accumulate constraints
            neo_constraints.bit_constraints.insert(
                neo_constraints.bit_constraints.end(),
                cs.bit_constraints.begin(), cs.bit_constraints.end()
            );
            neo_constraints.field_constraints.insert(
                neo_constraints.field_constraints.end(),
                cs.field_constraints.begin(), cs.field_constraints.end()
            );
            neo_constraints.small_field_constraints.insert(
                neo_constraints.small_field_constraints.end(),
                cs.small_field_constraints.begin(), cs.small_field_constraints.end()
            );
        }
        
        return neo_constraints;
    }

private:
    template<typename Field>
    std::vector<Field> encode_linear_commitment_constraint(
        const abeliangroup::SimpleConstraint<G>& constraint, 
        std::size_t commitment_index
    ) const {
        // Encode geometric constraint for Pedersen commitment opening
        // Format: [commitment_index, constraint_type, coefficients...]
        std::vector<Field> encoded;
        encoded.push_back(Field(commitment_index));
        encoded.push_back(Field(static_cast<int>(constraint.type)));
        
        // Add constraint-specific coefficients
        // This is a simplified encoding - actual implementation would depend
        // on the specific group representation and field arithmetic
        return encoded;
    }

    template<typename Field>
    std::vector<Field> encode_quadratic_commitment_constraint(
        const abeliangroup::SimpleConstraint<G>& constraint,
        std::size_t commitment_index
    ) const {
        // Encode conditional operations for commitment opening
        std::vector<Field> encoded;
        encoded.push_back(Field(commitment_index));
        encoded.push_back(Field(static_cast<int>(constraint.type)));
        
        // Add quadratic constraint coefficients for conditional operations
        return encoded;
    }
};

}

#endif
