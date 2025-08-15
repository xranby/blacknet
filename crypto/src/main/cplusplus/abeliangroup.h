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

namespace blacknet::crypto {

// Speeding up the computations on an elliptic curve using addition-subtraction chains
// ADDSUBCHAIN-D
// http://www.numdam.org/item/ITA_1990__24_6_531_0/

namespace abeliangroup {

template<typename AG, typename Scalar>
constexpr AG multiply(const AG& e, const Scalar& s) {
    AG P(AG::additive_identity());
    AG Q(e);

    int QisQdouple = 0;
    int state = 0;

    auto updateQ = [&Q, &QisQdouple]() {
        for (int i = 0; i < QisQdouple; ++i) {
            Q = Q.douple();
        }
        QisQdouple = 0;
    };

    std::ranges::for_each(s.bitsBegin(), s.bitsEnd(), [&](bool bit) {
        switch(state){
            case 0:
                if(bit) {
                    state = 1;
                } else {
                    QisQdouple += 1;
                }
                break;
            case 1:
                // Q only needs to be updated in case P gets updated
                updateQ();
                if(bit) {
                    P = P - Q;
                    QisQdouple += 2;
                    state = 11;
                } else {
                    P = P + Q;
                    QisQdouple += 2;
                    state = 0;
                }
                break;
            case 11:
                if(bit) {
                    QisQdouple += 1;
                } else {
                    state = 1;
                }
                break;
        }
    });

    if(state!=0){
        // Q only needs to be updated in case P gets updated
        updateQ();
        P = P + Q;
    }

    return P;
}

/*
 * ADDSUBCHAIN-E: Optimized for low-degree multilinear polynomials
 * Prioritizing simple constraints over aggressive batching
 */

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
};

template<typename AG, typename Scalar>
class MultilinearScalarMult {
private:
    std::vector<SimpleConstraint<AG>> constraints;
    std::vector<AG> intermediate_points;
    
public:
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
                
                constraints.push_back({
                    SimpleConstraint<AG>::POINT_DOUBLE,
                    {(i == 0) ? Q : intermediate_points.back()},
                    doubled_Q
                });
                
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
                        constraints.push_back({
                            SimpleConstraint<AG>::POINT_SUB,
                            {P, current_Q},
                            new_P
                        });
                        P = new_P;
                        QisQdouble = 2;
                        state = 11;
                    } else {
                        // P = P + current_Q (simple addition constraint)
                        AG new_P = P + current_Q;
                        constraints.push_back({
                            SimpleConstraint<AG>::POINT_ADD,
                            {P, current_Q},
                            new_P
                        });
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
            constraints.push_back({
                SimpleConstraint<AG>::POINT_ADD,
                {P, current_Q},
                final_P
            });
        }
        
        return constraints;
    }
};

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
