/*
 * Copyright (c) 2026 Blacknet contributors
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

use blacknet_kernel::verifiedcomputation::{
    Compute, Deploy, Error, F, ProgramRegistry, compute_fee, params,
};
use blacknet_snark::proof::prove;
use blacknet_vm::machine::Instruction;

macro_rules! alloc_vec { ($($x:expr),*) => { vec![$($x),*] } }

fn f(n: i32) -> F {
    F::from(n)
}

fn square_add() -> Vec<Instruction<F>> {
    vec![
        Instruction::Mul(2, 1, 1),
        Instruction::Add(3, 2, 1),
        Instruction::Halt,
    ]
}

#[test]
fn deploy_and_compute() {
    let mut registry = ProgramRegistry::new();
    let id = registry.deploy(Deploy { code: square_add() }).unwrap();
    let (io, proof) = prove(&square_add(), &[f(6)], 100).unwrap();
    assert_eq!(io.outputs[2], f(42)); // r3 = 36 + 6
    let tx = Compute {
        program_id: id,
        io,
        proof,
    };
    assert!(registry.validate(&tx).is_ok());
}

#[test]
fn double_deploy_rejected() {
    let mut registry = ProgramRegistry::new();
    registry.deploy(Deploy { code: square_add() }).unwrap();
    assert!(matches!(
        registry.deploy(Deploy { code: square_add() }),
        Err(Error::AlreadyDeployed)
    ));
}

#[test]
fn unknown_program_rejected() {
    let registry = ProgramRegistry::new();
    let (io, proof) = prove(&square_add(), &[f(2)], 100).unwrap();
    let id = blacknet_snark::commitment::commit(&square_add());
    let tx = Compute {
        program_id: id,
        io,
        proof,
    };
    assert!(matches!(registry.validate(&tx), Err(Error::UnknownProgram)));
}

#[test]
fn forged_compute_rejected() {
    let mut registry = ProgramRegistry::new();
    let id = registry.deploy(Deploy { code: square_add() }).unwrap();
    let (mut io, proof) = prove(&square_add(), &[f(6)], 100).unwrap();
    io.outputs[2] = f(1_000_000);
    let tx = Compute {
        program_id: id,
        io,
        proof,
    };
    assert!(matches!(registry.validate(&tx), Err(Error::Verify(_))));
}

#[test]
fn fee_is_execution_independent() {
    assert_eq!(compute_fee(0), params::VERIFY_FEE);
    assert_eq!(
        compute_fee(100),
        params::VERIFY_FEE + 100 * params::BYTE_FEE
    );
}

#[test]
fn verification_cache() {
    use blacknet_kernel::verifiedcomputation::VerificationCache;
    let mut registry = ProgramRegistry::new();
    let id = registry.deploy(Deploy { code: square_add() }).unwrap();
    let (io, proof) = prove(&square_add(), &[f(6)], 100).unwrap();
    let tx = Compute {
        program_id: id,
        io,
        proof,
    };
    let mut cache = VerificationCache::new();
    let hash = [7u8; 32];
    assert!(!cache.contains(&hash));
    assert!(cache.validate(&registry, hash, &tx).is_ok());
    assert!(cache.contains(&hash));
    // Hit path: even a tx that would fail verification passes on a cache
    // hit, which is exactly why entries are inserted only after success.
    assert!(cache.validate(&registry, hash, &tx).is_ok());
    cache.evict(&hash);
    assert!(!cache.contains(&hash));
}

#[test]
fn uniform_batch_end_to_end() {
    use blacknet_kernel::verifiedcomputation::{
        ComputeBatch, DeployUniform, UniformRegistry, compute_batch_fee,
    };
    use blacknet_snark::pipeline::{Shape, prove_aggregate, prove_execution};
    use blacknet_snark::witnesscommitment::CommitmentKey;

    const TEST_ROWS: usize = 8;
    let mut registry = UniformRegistry::new(TEST_ROWS);
    let id = registry
        .deploy(DeployUniform {
            code: square_add(),
            sample_inputs: alloc_vec![f(1)],
            fuel: 100,
        })
        .unwrap();

    // Prover side mirrors the deployment-derived shape and key.
    let shape = Shape::derive(square_add(), &[f(1)], 100).unwrap();
    let key = CommitmentKey::setup(shape.elements, TEST_ROWS);
    let executions: Vec<_> = [3i32, 7, 12]
        .iter()
        .map(|&x| prove_execution(&shape, &key, &[f(x)]).unwrap())
        .collect();
    let proof = prove_aggregate(&shape, &key, &executions).unwrap();

    let tx = ComputeBatch {
        program_id: id,
        proof,
    };
    assert!(registry.validate(&tx).is_ok());
    assert_eq!(
        compute_batch_fee(3, 1000),
        3 * blacknet_kernel::verifiedcomputation::params::VERIFY_FEE
            + 1000 * blacknet_kernel::verifiedcomputation::params::BYTE_FEE
    );
}
