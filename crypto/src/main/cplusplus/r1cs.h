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

#ifndef BLACKNET_CRYPTO_R1CS_H
#define BLACKNET_CRYPTO_R1CS_H

#include <ostream>
#include <random>
#include <stdexcept>
#include <utility>
#include <fmt/format.h>

#include "matrixsparse.h"
#include "vectordense.h"
#include "abeliangroup.h"

namespace blacknet::crypto {

template<typename E>
class R1CS {
    MatrixSparse<E> a;
    MatrixSparse<E> b;
    MatrixSparse<E> c;
public:
    using ElementType = E;

    constexpr R1CS(const MatrixSparse<E>& a, const MatrixSparse<E>& b, const MatrixSparse<E>& c)
        : a(a), b(b), c(c) {}
    constexpr R1CS(MatrixSparse<E>&& a, MatrixSparse<E>&& b, MatrixSparse<E>&& c)
        : a(std::move(a)), b(std::move(b)), c(std::move(c)) {}
    constexpr R1CS(R1CS&&) noexcept = default;
    constexpr ~R1CS() noexcept = default;

    constexpr R1CS& operator = (R1CS&&) noexcept = default;

    constexpr bool operator == (const R1CS&) const = default;

    constexpr std::size_t constraints() const {
        return a.rows();
    }

    constexpr std::size_t variables() const {
        return a.columns;
    }

    constexpr bool isSatisfied(const VectorDense<E>& z) const {
        if (variables() == z.size()) {
            return (a * z) * (b * z) == c * z;
        } else {
            throw std::runtime_error(fmt::format("Assigned {} variables instead of {} required", z.size(), variables()));
        }
    }

    constexpr bool isSatisfied(const VectorDense<E>& z, const VectorDense<E>& e) const {
        if (variables() == z.size()) {
            return error(z) == e;
        } else {
            throw std::runtime_error(fmt::format("Assigned {} variables instead of {} required", z.size(), variables()));
        }
    }

    constexpr void fold(
        const E& r,
        VectorDense<E>& z, VectorDense<E>& e,
        const VectorDense<E>& z1, const VectorDense<E>& e1,
        const VectorDense<E>& z2, const VectorDense<E>& e2
    ) const {
        const E& u1 = z1[0];
        const E& u2 = z2[0];
        VectorDense<E> z12{ z1 + z2 };
        VectorDense<E> t{ (a * z12) * (b * z12) - (u1 + u2) * (c * z12) - e1 - e2 };
        z = z1 + r * z2;
        e = e1 + r * t + r.square() * e2;
    }

    constexpr VectorDense<E> assigment(E&& constant = E::multiplicative_identity()) const {
        VectorDense<E> z;
        z.elements.reserve(variables());
        z.elements.emplace_back(constant);
        return z;
    }

    friend std::ostream& operator << (std::ostream& out, const R1CS& val)
    {
        return out << '[' << val.a << ", " << val.b << ", " << val.c << ']';
    }

    template<typename Sponge>
    constexpr std::pair<VectorDense<E>, VectorDense<E>> squeeze(Sponge& sponge) const {
        auto z = VectorDense<E>::squeeze(sponge, variables());
        return { z, error(z) };
    }

    template<std::uniform_random_bit_generator RNG>
    std::pair<VectorDense<E>, VectorDense<E>> random(RNG& rng) const {
        auto z = VectorDense<E>::random(rng, variables());
        return { z, error(z) };
    }
    // Generate R1CS constraints for elliptic curve scalar multiplication using ADDSUBCHAIN-E
    template<typename ECGroup, typename Scalar>
    static constexpr R1CS<E> elliptic_curve_scalar_mult_r1cs(
        const ECGroup& base_point, 
        const Scalar& scalar_value,
        std::size_t additional_variables = 0
    ) {
        // Use ADDSUBCHAIN-E to generate optimized constraint system
        abeliangroup::ProofSystemOptimizedMult<ECGroup, Scalar, E> mult;
        auto constraint_system = mult.generate_constraint_system(base_point, scalar_value);
        
        // Calculate required variables: base point (2) + scalar (1) + result (2) + intermediates
        std::size_t num_variables = 6 + additional_variables;
        std::size_t num_constraints = constraint_system.linear_constraints.size() + 
                                     constraint_system.quadratic_constraints.size();
        
        // Initialize sparse matrices for R1CS: Az * Bz = Cz
        MatrixSparse<E> a_matrix(num_constraints, num_variables);
        MatrixSparse<E> b_matrix(num_constraints, num_variables);
        MatrixSparse<E> c_matrix(num_constraints, num_variables);
        
        std::size_t constraint_idx = 0;
        
        // Convert linear constraints to R1CS format
        // For linear constraint: x1 + x2 - x3 = 0
        // Convert to: (x1 + x2 - x3) * 1 = 0
        for (const auto& linear_constraint : constraint_system.linear_constraints) {
            for (std::size_t var_idx = 0; var_idx < linear_constraint.size() && var_idx < num_variables; ++var_idx) {
                if (linear_constraint[var_idx] != E(0)) {
                    a_matrix.cIndex.push_back(var_idx);
                    a_matrix.elements.push_back(linear_constraint[var_idx]);
                }
            }
            a_matrix.rIndex.push_back(a_matrix.elements.size());
            
            // B matrix: constant 1
            b_matrix.cIndex.push_back(0);  // constant variable
            b_matrix.elements.push_back(E(1));
            b_matrix.rIndex.push_back(b_matrix.elements.size());
            
            // C matrix: 0 (since we want the result to be 0)
            c_matrix.rIndex.push_back(c_matrix.elements.size());
            
            constraint_idx++;
        }
        
        // Convert quadratic constraints to R1CS format
        // For quadratic constraint: bit * (x1 + x2 - x3) + (1-bit) * (x1 - x3) = 0
        // This is already in the form: A * B = C where A and B contain the factors
        for (const auto& quad_constraint : constraint_system.quadratic_constraints) {
            if (quad_constraint.size() >= 4) {
                // A matrix: bit coefficient
                a_matrix.cIndex.push_back(2);  // scalar bit variable
                a_matrix.elements.push_back(E(1));
                a_matrix.rIndex.push_back(a_matrix.elements.size());
                
                // B matrix: (x1 + x2 - x3) term
                for (std::size_t i = 0; i < 3 && i < quad_constraint.size(); ++i) {
                    if (quad_constraint[i] != E(0)) {
                        b_matrix.cIndex.push_back(3 + i);  // point variables
                        b_matrix.elements.push_back(quad_constraint[i]);
                    }
                }
                b_matrix.rIndex.push_back(b_matrix.elements.size());
                
                // C matrix: result should be 0
                c_matrix.rIndex.push_back(c_matrix.elements.size());
            }
            constraint_idx++;
        }
        
        return R1CS<E>(std::move(a_matrix), std::move(b_matrix), std::move(c_matrix));
    }
    
    // Generate R1CS for multiple elliptic curve operations
    template<typename ECGroup, typename Scalar>
    static constexpr R1CS<E> batch_elliptic_curve_r1cs(
        const std::vector<ECGroup>& points,
        const std::vector<Scalar>& scalars
    ) {
        if (points.size() != scalars.size()) {
            throw std::runtime_error("Points and scalars vectors must have the same size");
        }
        
        std::vector<MatrixSparse<E>> a_matrices, b_matrices, c_matrices;
        a_matrices.reserve(points.size());
        b_matrices.reserve(points.size());
        c_matrices.reserve(points.size());
        
        // Generate R1CS for each scalar multiplication
        for (std::size_t i = 0; i < points.size(); ++i) {
            auto individual_r1cs = elliptic_curve_scalar_mult_r1cs(points[i], scalars[i]);
            a_matrices.push_back(std::move(individual_r1cs.a));
            b_matrices.push_back(std::move(individual_r1cs.b));
            c_matrices.push_back(std::move(individual_r1cs.c));
        }
        
        // Combine matrices (simplified - actual implementation would handle variable indexing)
        auto combined_a = concatenate_matrices(a_matrices);
        auto combined_b = concatenate_matrices(b_matrices);
        auto combined_c = concatenate_matrices(c_matrices);
        
        return R1CS<E>(std::move(combined_a), std::move(combined_b), std::move(combined_c));
    }

private:
    constexpr VectorDense<E> error(const VectorDense<E>& z) const {
        const E& u = z[0];
        return (a * z) * (b * z) - u * (c * z);
    }
    
    // Helper function to concatenate sparse matrices
    static MatrixSparse<E> concatenate_matrices(const std::vector<MatrixSparse<E>>& matrices) {
        if (matrices.empty()) {
            return MatrixSparse<E>(0, 0);
        }
        
        std::size_t total_rows = 0;
        std::size_t max_columns = 0;
        
        for (const auto& matrix : matrices) {
            total_rows += matrix.rows();
            max_columns = std::max(max_columns, matrix.columns);
        }
        
        MatrixSparse<E> result(total_rows, max_columns);
        
        for (const auto& matrix : matrices) {
            // Append matrix elements and indices
            result.elements.insert(result.elements.end(), 
                                 matrix.elements.begin(), matrix.elements.end());
            result.cIndex.insert(result.cIndex.end(),
                                matrix.cIndex.begin(), matrix.cIndex.end());
            
            // Adjust row indices
            for (std::size_t i = 0; i < matrix.rIndex.size(); ++i) {
                result.rIndex.push_back(matrix.rIndex[i] + result.elements.size() - matrix.elements.size());
            }
        }
        
        return result;
    }
};

}

#endif
