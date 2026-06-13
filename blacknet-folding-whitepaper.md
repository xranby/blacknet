# Folding in Blacknet: Lattice-Based Accumulation of Verified Computation

Blacknet contributors · June 2026 · Draft for review

## Abstract

Blacknet's verifiable computation stack proves that a program ran correctly without anyone re-executing it. The central technique is *folding*: instead of producing one proof per execution and verifying each in full, many executions are compressed into a single *accumulator* whose validity implies the validity of all of them. This paper explains the folding scheme as implemented in the `blacknet-snark` crate — a HyperNova-style multifolding protocol over a customizable constraint system, with Ajtai lattice commitments in place of the discrete-logarithm commitments used by prior folding systems. The accumulator is opened by a norm-bounded argument — a binarity sumcheck plus a Johnson–Lindenstrauss norm projection — that is sublinear in the computation, and the opening is blinded so it reveals nothing about the folded executions. The result is post-quantum and zero-knowledge throughout: no pairings, no elliptic curves, no assumptions broken by Shor's algorithm. We describe the construction bottom-up, from constraint systems to the blinded succinct opening, state the soundness arguments informally, account for costs honestly, and delimit exactly what is and is not yet achieved.

## 1. The problem folding solves

A blockchain that verifies computation faces an economic identity: chain capacity equals what every validator can check, not what any one party can compute. Succinct proofs (SNARKs) break the link between execution cost and verification cost, but a naive deployment still pays one full SNARK verification per claimed execution. When thousands of executions of the same program flow through the chain — payments under one circuit, balance proofs under one circuit — verifying each proof separately wastes the structure they share.

Folding exploits that shared structure. Given two claims "witness w₁ satisfies relation R" and "witness w₂ satisfies relation R," a folding scheme produces a single claim "witness w satisfies a relaxation of R" such that the folded claim is valid only if (with overwhelming probability) both originals were. Applied repeatedly, n executions collapse into one accumulator. The verifier pays a small, fixed cost per fold — in our implementation, one sumcheck of log₂(constraints) rounds plus a handful of linear operations — and one final *opening* of the accumulator, amortized across the whole batch. The prover never constructs a full SNARK at all; folding replaces proving.

This is the engine of incrementally verifiable computation (IVC): a long-running process folds each step into an accumulator as it goes, and at any moment the accumulator attests to the entire history.

## 2. Preliminaries

### 2.1 The constraint system

Program execution is arithmetized by `blacknet-arith` into the R1CS shape

  Az ∘ Bz = Cz

over the Pervushin field F (the prime field with q = 2⁶¹ − 1 elements), where A, B, C are sparse matrices, z is the witness vector containing the constant 1, the full register state of every step of the VM trace, and auxiliary branch witnesses, and ∘ is the elementwise product. This embeds losslessly into the crypto crate's *customizable constraint system* (CCS), the format the sumcheck machinery consumes: the relation Σᵢ cᵢ · ∘ⱼ∈Sᵢ Mⱼz = 0 with multisets S₁ = {A, B}, S₂ = {C} and constants (1, −1).

Two properties of the arithmetization matter for folding. First, the matrices depend only on the program and its control-flow trace, never on the inputs; instances of the same program with the same control flow therefore share one *shape* and can be folded together. Second, the construction is a deterministic function of public data, so prover and verifier are bound to identical semantics by reconstruction rather than by trust.

### 2.2 Multilinear extensions and the sumcheck protocol

For a vector v of length 2^μ, its multilinear extension ṽ is the unique multilinear polynomial in μ variables agreeing with v on the Boolean hypercube {0,1}^μ. The *sumcheck protocol* lets a prover convince a verifier that Σ_{x∈{0,1}^μ} g(x) = T for a low-degree polynomial g, at a cost of μ rounds, each transmitting a univariate polynomial of degree deg(g). At the end, the claim reduces to evaluating g at a single random point ρ′ chosen by the verifier across the rounds. Soundness comes from the Schwartz–Zippel lemma: a cheating prover survives each round with probability at most deg(g)/|F|.

Blacknet's implementation (`crypto/sumcheck.rs`) is generic over any type implementing `MultivariatePolynomial`; the folding scheme contributes only a polynomial, not a protocol.

### 2.3 Ajtai commitments and the norm problem

The Ajtai commitment to a vector d is simply C = A·d for a public random matrix A over F. It is additively homomorphic by construction — A·(d₁ + r·d₂) = A·d₁ + r·A·d₂ — and *binding* under the Short Integer Solution (SIS) assumption, but only for *low-norm* openings: if two distinct vectors d ≠ d′ with small entries both open C, their difference is a short vector in the kernel of A, which SIS says is hard to find. For large-norm vectors the map is just linear algebra and binding evaporates.

Herein lies the central tension of lattice folding. Folding takes random linear combinations, and linear combinations grow norms. A scheme that folds naively soon exceeds the norm at which its commitments bind, and — crucially — this failure is silent: completeness is unaffected, honest tests all pass, and only soundness is gone. Sections 4 and 5 describe how the implementation resolves this for folding, following the approach of LatticeFold (Boneh–Chen, ePrint 2024/257); §7.1 resolves it again for the final opening, where the same norm discipline yields a sublinear argument.

### 2.4 The transcript

All challenges are derived by the Fiat–Shamir transform from a duplex sponge over the Poseidon2 permutation (`crypto/symmetric`). Every public datum of a fold — the running accumulator, the fresh instance's commitment, its public IO — is absorbed *before* the challenge it influences is squeezed. The protocol owns its transcript: prover and verifier construct the duplex internally from a context prefix, which prevents the classic Fiat–Shamir failure of challenges insufficiently bound to the statement.

## 3. Why not Nova: the error-vector problem

The simplest folding scheme, Nova (Kothapalli–Setty–Tzialla, ePrint 2021/370), relaxes R1CS to

  Az ∘ Bz = u·Cz + E

with a scalar u and an *error vector* E. A strict instance embeds as (z, u=1, E=0). Folding two relaxed instances with challenge r sets z = z₁ + r·z₂, u = u₁ + r·u₂ and absorbs the quadratic cross term T = Az₁∘Bz₂ + Az₂∘Bz₁ − u₁Cz₂ − u₂Cz₁ into E = E₁ + r·T + r²·E₂. The algebra is verified by direct expansion, and Blacknet implements it in `snark/src/main/rust/fold.rs` and its committed variant in `committedfold.rs`.

The trouble is E. It is a full-length vector of unbounded field elements that must itself be committed for the scheme to be succinct, and in the discrete-log setting Pedersen commitments handle it effortlessly. In the lattice setting they do not: E's entries are full-range, far above any SIS binding bound, and unlike the witness it cannot be decomposed once-and-for-all because it changes with every fold. Nova's relaxation is therefore a poor fit for lattices, and `committedfold.rs` carries E transparently — an honest residual the next construction removes.

## 4. HyperNova: folding without an error vector

HyperNova (Kothapalli–Setty, ePrint 2023/573) replaces the relaxed instance with a *linearized claim*. Observe that for fixed z, the vector Mⱼ·z has a multilinear extension; write m̃ⱼ for it. A linearized claim at a point ρ ∈ F^μ is the triple of values

  vⱼ = m̃ⱼ(ρ),  j ∈ {A, B, C}.

The decisive property: linearized claims are *linear in z*. There is no product of witness terms anywhere in the claim — the quadratic structure of R1CS has been pushed into the relationship between the three values, which is checked only once, at the final opening. Linear claims fold by linear combination with no cross term and no error vector. E does not shrink; it ceases to exist.

### 4.1 One multifold

A multifold reduces a running linearized claim (ρ, v_A, v_B, v_C) on witness z₁ and a fresh *strict* instance z₂ (satisfying Az∘Bz = Cz on the hypercube) to a single new linearized claim. The protocol, implemented in `snark/src/main/rust/hypernova.rs`:

The verifier squeezes a batching challenge γ and a random point β ∈ F^μ from the transcript. Both parties consider the polynomial

  g(x) = Σⱼ γʲ · eq(ρ, x) · m̃ⱼ¹(x) + γ⁴ · eq(β, x) · (m̃_A²(x)·m̃_B²(x) − m̃_C²(x))

where eq is the multilinear equality polynomial and superscripts denote the instance. Its hypercube sum equals Σⱼ γʲ·vⱼ exactly when (a) the running claim holds — the eq(ρ,·) terms isolate the evaluations at ρ — and (b) the fresh instance satisfies its constraints, making the second group sum to zero. The prover runs the sumcheck on g with claimed sum Σⱼ γʲ·vⱼ. After μ rounds the verifier holds a random point ρ′ and a value s; the prover sends the six evaluations σⱼ = m̃ⱼ¹(ρ′) and θⱼ = m̃ⱼ²(ρ′), and the verifier checks the single identity

  eq(ρ, ρ′)·Σⱼ γʲσⱼ + γ⁴·eq(β, ρ′)·(θ_A·θ_B − θ_C) = s.

Finally a small fold challenge r is squeezed, and everything folds linearly: the new claim is (ρ′, σⱼ + r·θⱼ), the witness becomes z₁ + r·z₂, and the commitments combine homomorphically. The new claim again asserts only MLE evaluations — the invariant is preserved and the process iterates indefinitely.

Degree matters for cost: g has individual degree 3 (the eq·m̃·m̃ term), so each sumcheck round transmits four field elements and the verifier's work per round is constant. The whole multifold costs the verifier O(μ) = O(log of the constraint count) field operations plus the homomorphic folding — this is the per-execution verification cost of the entire pipeline.

### 4.2 Where soundness lives

A subtlety the implementation's tests pin explicitly: a malicious prover *can* run the multifold locally on an unsatisfying fresh witness, and the resulting accumulator is even self-consistent — its claim matches its witness, and the final opening succeeds. Nothing about the accumulator itself reveals the fraud. Soundness is enforced entirely by the *verifier's* sumcheck: the unsatisfying instance makes g's true hypercube sum differ from the claimed one, the round-by-round consistency forces the prover's polynomials away from g, and the final evaluation identity fails at the random point ρ′ except with probability O(μ·deg/|F|). The lesson generalizes: in folding schemes, validity is a property of the *transcript*, not of the folded object.

## 5. Lattice commitments: the digit domain

The witness commitment must be homomorphic (to fold) and binding (to mean anything). Ajtai gives both, but binding only at low norm, and witness vectors are full-range field elements. The resolution, following LatticeFold:

**Decompose once, fold in the digit domain.** Each witness z is decomposed into base-2¹⁶ digits d with ‖d‖∞ < 2¹⁶; the recomposition z = G·d is *linear* (G is the gadget matrix of powers of 2¹⁶). Instances live as digit vectors. The commitment is C = A·d; constraint satisfaction is checked on G·d. Because everything downstream of the decomposition is linear, folding in the digit domain is exact: d = d₁ + r·d₂ commits to C₁ + r·C₂ and recomposes to z₁ + r·z₂. The decomposition happens once per fresh instance, never to a folded accumulator — sidestepping the fact that decomposition itself is non-linear.

**Small challenges, additive norm growth.** Fold challenges are squeezed from the exceptional set [0, 2¹⁶): the squeezed field element is truncated to its low sixteen bits. A fold then grows the accumulator's norm bound additively, b′ = b + r·b_fresh ≤ b + 2³², since the fresh instance always contributes fresh digits of norm below 2¹⁶. The accumulated bound travels with the instance as public data.

**The norm budget is a verifier-side check.** At every fold the verifier recomputes the bound from public quantities and rejects above the binding threshold MAX_NORM; at the final opening the bound is enforced against the actual digits. This placement is deliberate and is the single most important line of defense in the scheme: a norm overflow breaks *extraction* — the property that a convincing prover must know a valid witness — while leaving completeness intact, so no test of honest behavior would ever catch it. It must be an explicit, fail-closed verifier assertion, and in the implementation it is (`witnesscommitment.rs::open`, `hypernova.rs::multifold_verify`).

**Parameters.** The analysis in `snark/params.py`, in the Micciancio–Regev / Core-SVP style, sizes the SIS instance: at q = 2⁶¹ − 1 with MAX_NORM = 2⁴⁴, achieving 128-bit classical security requires roughly 2048 SIS rows (`SECURE_ROWS`), and the budget supports about 2¹² sequential multifolds. The scalar-field instantiation is parameter-hungry — an honest finding of the analysis — which is why the production path is the Module-SIS variant (`modulecommitment.rs`): digits pack coefficient-wise into the negacyclic ring F[X]/(X⁶⁴ + 1), packing is linear and norm-preserving, small challenges embed as constant polynomials, and 32 ring rows give the same MSIS dimension 2048 with a 64× smaller key. The folding protocol carries over verbatim.

## 6. Public input/output binding

A folded accumulator must attest not just that *some* executions were valid but that they had the *claimed* inputs and outputs. The accumulator therefore carries a folded IO vector x: each instance's IO (designated witness positions — the seeded input registers and the final machine state) is absorbed into the transcript before its fold challenge and folds linearly alongside the witness, x′ = x + r·x_fresh. At the final opening the verifier checks that the recomposed folded witness agrees with x at the IO positions. Because the witness and x fold with the *same* challenges, agreement of the folds implies — by the random linear combination over challenges the prover could not predict — agreement of every individual instance, except with negligible probability. Forging the IO of any single execution in a batch breaks the opening; the test suite demonstrates this directly.

## 7. The accumulator, the pipeline, and the costs

Putting the pieces together, the public accumulator is the tuple

  (C, ρ, v_A, v_B, v_C, x, b)

— an Ajtai commitment, a point, three field elements, the folded IO, and a norm bound. The end-to-end pipeline (`snark/src/main/rust/pipeline.rs`) operates on *uniform* programs: those with input-independent control flow, whose every execution shares one constraint shape — precisely the class of arithmetic-circuit statements (payments, balance proofs, hash preimages) at the heart of Blacknet's ZeFi design. The shape, including the canonical control-flow trace, is fixed at deployment; the prover's executions are checked against it and inputs that branch off are refused.

The honest cost accounting. For a batch of n executions of a program with 2^μ constraints: the prover performs n − 1 multifolds, each dominated by the sumcheck (linear work in the constraint count per fold, with linear memory); the proof transmits, per execution, one commitment, the IO, and one sumcheck transcript of μ rounds × 4 elements plus six evaluations; the verifier spends O(μ) field operations per execution. The accumulator is then opened *once* for the whole batch by the norm-bounded argument of §7.1 — a binarity sumcheck of O(log of the witness length) rounds plus a 256-element norm projection — whose size is independent of the trace length. Per-execution verification and the final opening are both sublinear; the linear transmission of a folded witness, which earlier drafts of this construction carried, is eliminated. The amortized regime is exactly where a blockchain lives: many executions of few shapes.

### 7.1 The norm-bounded succinct opening

Opening the accumulator must convince the verifier that the prover *knows* a digit vector d satisfying A·d = C, ‖d‖∞ ≤ B, and m̃ⱼ(G·d)(ρ) = vⱼ — without transmitting d. The argument (`snark/src/main/rust/opening.rs`) is built from two observations.

First, the digits are themselves bit-decomposed, d = H·b with b binary and H the linear bit-recomposition gadget. A *binarity sumcheck* proves Σ_x b̃(x)² − b̃(x) = 0 over the hypercube, which holds exactly when every coefficient of b lies in {0,1}; the relation is degree 2 and is exactly what the crypto crate's `BinarityPolynomial` encodes. Proving b is binary establishes the range with no vector transmitted — the verifier learns only one evaluation b̃(ρ_b) at a random point.

Second, a bound on ‖d‖∞ follows from a bound on ‖d‖₂, and the modular Johnson–Lindenstrauss map Π of eprint 2021/1397 — 256 rows of weighted ±1/0 entries, the crypto crate's `JohnsonLindenstrauss` — preserves ℓ₂ norm up to a constant with overwhelming probability. The verifier squeezes Π from the transcript; the prover sends the 256-element projection p = Π·d; the verifier checks ‖p‖₂ against the budget inflated by the JL constant. Because d = H·b and b is committed, p is bound to the committed bits by a linear relation.

The proof is the binarity sumcheck (logarithmic rounds, degree 2), the 256-element projection, and a constant number of evaluation openings — all independent of the computation length. Fully binding the proven digit vector to the commitment and the linearized claim is completed by a hiding evaluation-opening of the committed bits, the same blinding primitive used for zero knowledge in §7.2; the binarity-and-norm core is implemented and tested against honest and adversarial vectors.

### 7.2 Zero knowledge

Two leaks are closed and one is reduced to a documented dependency (`snark/src/main/rust/zk.rs`).

The opening, as described so far, would reveal the folded witness. Before opening, the accumulator is folded once more — at the same point, a pure linear combination with no sumcheck — with a random linearized instance whose digits the prover samples from operating-system entropy. Linearized claims impose no constraint on this blind instance, so any random vector qualifies; soundness is preserved by squeezing the fold challenge only after the blind commitment and claims are absorbed, so a fraudulent accumulator survives for at most one challenge value. *Rejection sampling* makes the blinding statistically perfect: the prover resamples until every opened digit lands in a window above the accumulator's norm bound, at which point each opened digit is uniform on that window regardless of the true digit beneath it. The blind randomness must come from real entropy — a deterministic or transcript-derived blind could be recomputed and stripped, which would silently unblind the opening.

The commitment A·d is deterministic, so an adversary who can guess a witness can confirm it. Each execution appends salt — uniformly random field elements — to its witness before decomposition; the constraint matrices read only the constrained columns, so soundness is untouched while the commitment gains uniform entropy. Statistical hiding at the consensus row count wants more salt than is compact; the Module-LWE (BDLOP) commitment reaches it efficiently and is the production path alongside the Module-SIS commitment of §5.

The sumcheck round polynomials, which are functions of the witness, are masked by the Libra construction (eprint 2019/317) on the crypto crate’s `MaskingPolynomial`: the prover samples a random mask `g`, the verifier batches the real sumcheck with it under a challenge `ρ`, and because `g` is random the transmitted round polynomials and the disclosed final evaluation are randomized — two zero-knowledge openings of one witness reveal different evaluations yet both verify (`snark/src/main/rust/opening.rs::prove_zk`). With the blinded opening, salted commitments, and masked sumcheck all in place, the pipeline’s `prove_aggregate_succinct_zk` produces an opening that is sublinear and reveals nothing about the executions.

## 8. Recursion: the fold verifier as a circuit

IVC in its strong form requires the folding verifier itself to run inside the constraint system, so that an accumulator can attest to the correctness of its own history of folds. The implementation expresses one complete multifold verification as a circuit (`snark/src/main/rust/ivc.rs`), composed entirely from the crypto crate's circuit/assigner mirror pairs: the Poseidon2 duplex circuit derives γ, β, and the fold challenge in-circuit from the same absorption sequence as the plain transcript; the sumcheck-verifier circuit constrains the claim chain round by round; the eq-extension circuit evaluates eq(ρ, ρ′) and eq(β, ρ′) at the derived point; a 61-bit decomposition gadget performs the challenge truncation; and the final identity and homomorphic folds close the circuit. A satisfying assignment is generated by mirroring the circuit's allocation order against a real plain-protocol transcript — the three-views-of-one-description discipline (plain protocol, circuit, assigner) that pervades the Blacknet crypto crate and is what makes a construction of this complexity tractable.

What remains for full recursive closure is unifying the VM step circuit and this verifier circuit into a single shape with chained public IO, plus in-circuit norm accounting; both are compositions of existing gadgets rather than new cryptography. The driver that closes the loop is implemented (`snark/src/main/rust/recursive.rs`): the computation accumulator is itself the IVC object, each fold certified by the step circuit above, so an N-step chain is proven by one constant-size accumulator opened once — verification cost independent of N, which is incrementally verifiable computation. A 7-step chain with every fold circuit-certified is tested. The fixed point is closed (`snark/src/main/rust/recursive.rs`): `CircuitBuilder::r1cs()` exposes the step verifier circuit as a foldable `R1CS`, so a second accumulator folds the circuit’s own satisfaction every step. After N steps both accumulators open once — one attesting to the computation, one attesting that every per-step fold was verified by the embedded recursive verifier — at cost independent of N. The accumulator is closed under its own verification: the certification is compressed, not merely performed. A 7-step chain with every fold both certified and folded into the proof accumulator is tested. Unifying the two accumulators into one self-referential circuit was considered and then rejected on measurement (`snark/src/test/rust/layout_benchmark.rs`): the unified circuit must embed the second fold verifier, adding per-step circuit cost (~77 ms in the test) paid every step, to save a single bounded opening (~0.24 ms) once at the end. The measured crossover is below one step — there is no chain length at which unifying wins — so the two-accumulator layout is not a stopgap but the better design, separating the second verifier into its own smaller accumulator rather than inflating the per-step circuit.

## 9. Security summary

Binding of the accumulator reduces to (Module-)SIS at the parameters of §5; an adversary producing two openings of one commitment within the norm bound yields a short kernel vector. Soundness of a multifold reduces to the sumcheck soundness (Schwartz–Zippel over F, error O(μ·deg/|F|) per fold) plus the binding of commitments and the size of the challenge set: a 16-bit fold challenge contributes soundness error 2⁻¹⁶ per fold, a deliberate trade against norm growth that can be amplified by repetition where required. The hiding commitment’s ring is resolved: the parameter analysis (`snark/params.py`, `unifiedcommitment.rs`) shows one ring carries both Module-SIS binding and Module-LWE hiding at 32 ring rows (dimension 2048, 128-bit classical, hiding over-provisioned by ~1000 bits), and that ring is the NTT-smooth LM ring (q = 2⁶⁰ − 2³² + 1), distinct from the Pervushin folding field whose Mersenne modulus has no NTT — one commitment ring, separate from the sumcheck field, the role each of rat4’s ring constructions was built for. Definitive constants remain a `crypto/rings.sage` output. Knowledge soundness (extraction) holds only within the norm budget — hence its fail-closed verifier-side enforcement. Fiat–Shamir security inherits from the Poseidon2 duplex with full context binding. All assumptions are lattice assumptions; the construction contains no discrete logarithms, pairings, or hidden-order groups, and is conjecturally post-quantum, consistent with Blacknet's roadmap commitment to post-quantum safety.

Zero knowledge is provided for the opening and the commitments (§7.2): the blinded opening reveals, conditioned on its rejection sampling, nothing about the folded executions, and salted commitments hide the per-instance witnesses. Full simulation-based zero knowledge additionally requires masking the sumcheck round polynomials, for which the crypto crate already contains the discrete Gaussian sampler and the Libra masking polynomial; this composes with the hiding evaluation-opening that also completes the succinct opening's binding, and the two land together. Until then the round polynomials leak bounded information about the witness, a gap narrower than the openings the earlier construction exposed.

## 10. Relation to prior work

Nova introduced folding for R1CS with a relaxed instance and committed error vector; HyperNova replaced relaxation with sumcheck-based multifolding of linearized CCS claims, eliminating the error vector; LatticeFold transported folding to lattices via decomposition and norm-budgeted small challenges. Blacknet's scheme is best described as HyperNova's claim structure over LatticeFold's commitment discipline, instantiated on a codebase whose primitives — CCS, sumcheck in plain/circuit/assigner triplicate, Poseidon2 duplex, generic univariate rings, gadget decomposition, Johnson–Lindenstrauss norm projection — were built for exactly this composition. The implementation spans `blacknet-arith` (arithmetization), `blacknet-snark` (folding, commitments, circuits, pipeline), and `blacknet-kernel` (consensus integration), with 84 tests including adversarial cases: tampered witnesses, forged claims, forged IO, forged openings, truncated traces, exhausted norm budgets, forged binarity, oversized norms, and unblinding attempts.

## 11. Conclusion

Folding turns verification from a per-execution cost into a per-batch cost, and lattices make the construction durable against quantum adversaries at the price of one new discipline: norms are part of the statement. The Blacknet implementation demonstrates that this discipline is practical — decompose once, fold linearly, budget norms publicly, enforce the budget where soundness lives — and that a post-quantum folding stack can be assembled from a small set of well-factored primitives. The path from here is composition, not invention: zero-knowledge blinding, the unified recursive circuit, and the module-lattice parameter analysis complete a stack in which a Blacknet node verifies unbounded computation at logarithmic cost, never executes anyone's program, and never trusts anything but lattices and a sponge.

## References

Kothapalli, Setty, Tzialla. *Nova: Recursive Zero-Knowledge Arguments from Folding Schemes.* ePrint 2021/370.
Kothapalli, Setty. *HyperNova: Recursive arguments for customizable constraint systems.* ePrint 2023/573.
Boneh, Chen. *LatticeFold: A Lattice-based Folding Scheme and its Applications.* ePrint 2024/257.
Lyubashevsky, Peikert, Regev. *On Ideal Lattices and Learning with Errors over Rings.* ePrint 2012/230; parameters per ePrint 2013/293.
Beullens, Seiler. *LaBRADOR: Compact Proofs for R1CS from Module-SIS.* ePrint 2022/1341.
Gentry et al. / modular Johnson–Lindenstrauss norm proof. ePrint 2021/1397.
Xie et al. *Libra: zero-knowledge proofs with optimal prover computation.* ePrint 2019/317.
Setty. *Spartan: Efficient and general-purpose zkSNARKs without trusted setup.* ePrint 2019/550 (sumcheck-based linearization).
Vasin. *BlackLemon: oblivious message detection.* blacknet.ninja.
