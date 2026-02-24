# Registered-Attribute-Based-Encryption

This project implements a Registered Attribute-Based Encryption (R-ABE) scheme using a modular Witness Encryption (WE) framework.

## Project Overview

This project implements a **Registered Attribute-Based Encryption (R-ABE)** scheme for DNF policies with a **linear-sized Common Reference String (CRS)**. This system allows users to generate their own keys and register them with a key curator, removing the need for a fully trusted central authority.

### Key Features

* **Linear CRS**: The size of the Common Reference String grows linearly with the number of users ($O(M)$).
* **Modular Framework**: Built using a Witness Encryption framework based on linearly verifiable SNARK gadgets (Inner Product, Signature, MaxDegree, Zero Check).
* **DNF Policies**: Supports access control policies expressed as Disjunctive Normal Form (DNF) formulas.
* **Standard Assumptions**: The construction is purely algebraic, uses KZG polynomial commitments, and is proven secure in the Generic Group Model (GGM).

### Technical Details

The construction reduces the R-ABE relation to a routed product of simpler relations:
$$\text{IIP} \times \text{NonZero} \times \text{DLOG} \times \text{Zero}_1 \times \dots \times \text{Zero}_k$$

This modular approach ensures succinctness and efficiency by composing "gadgets", special-purpose witness encryption schemes for targeted relations.

## Setup

Before starting to use this repository, please ensure that you have the following installed on your system.

### Requirements

* **Rust and Cargo**
    * **Recommended Version:** `1.91.0` (for both `rustc` and `cargo`)

To check if Rust and Cargo are installed and working correctly, run:
```bash
cargo --version
rustc --version
```
### Optional

If you plan to modify the repo, you can use:
* [**VS Code**](https://code.visualstudio.com/download)
* **Rust Analyzer Extension:** [rust-analyzer](https://marketplace.visualstudio.com/items?itemName=rust-lang.rust-analyzer)


### Configuration & Running
You can configure the users by editing the configuration file located at: `src/users_configs.json`

To run with the default configuration:

```bash
> cargo run
```
To run with a custom configuration file:

```bash
> cargo run <path/to/your/config.json>
```

### Configuration File
The system behavior and user setup are defined through a JSON configuration file. This file specifies the number of users in the system and the attribute sets associated with each user. It is used by the setup, key generation, aggregation, and encryption/decryption phases to simulate a complete R-ABE environment.

#### File Location

By default, the configuration file is located at: `src/users_configs.json` 

#### File Structure

The configuration file must follow the JSON schema below:

```{
  "user_count": <integer>,
  "users": [
    {
      "user_id": <integer>,
      "attributes": [ "<string>", "<string>", ... ]
    }
  ]
 }
```


### Field Description

#### `user_count`

-   **Type:** `integer`
    
-   **Description:**  
    The total number of users in the system.  
    This value defines:
    
    -   The maximum number of users `M`
    -   The size of the CRS (`O(M)`)
    -   The dimension of public key vectors and aggregation structure
   
	Must match the number of entries in the `users` array.

----------

#### `users`

-   **Type:** `array`
    
-   **Description:**  
    List of all registered users in the system.
    

Each user object contains:

##### `user_id`

-   **Type:** `integer`
    
-   **Description:**  
    A unique identifier for the user.  
    This ID is used internally for:
    -   Indexing in CRS powers
    -   Zero-check polynomials
    -   Aggregation partitions
    -   Helper key generation
    Must be unique.

##### `attributes`

-   **Type:** `array of strings`
    
-   **Description:**  
    The attribute set associated with the user.  
    Attributes are treated as **strings** and have no internal structure from the system’s perspective.
    

Examples:

`"role:admin"  "department:finance"  "location:NY"` 

These attributes are:

-   Collected into the `Ueff`
-   Used to build ZeroCheck polynomials
-   Used for user partitioning during aggregation
-   Matched against DNF policy literals during decryption

## Technologies used

The implementation is written in Rust and relies on the `arkworks` cryptographic ecosystem. Rust is well suited for this project because it offers low-level control and performance comparable to C/C++, while enforcing memory safety and preventing common implementation errors that are important in cryptographic code. Its strong type system also helps model algebraic objects in an explicit way.

The `arkworks` libraries are used because they provide efficient, tested implementations of finite field arithmetic, elliptic curves, and bilinear pairings, which are the building blocks of the R-ABE construction. In particular, `ark-ff` and `ark-ec` are used for field and group operations, and `ark-bls12-381` provides the pairing-friendly curve required by the scheme. Arkworks exposes these primitives, making it possible to closely follow the algebraic structure of the construction without introducing unnecessary abstractions. 

This makes it a good fit for implementing modular cryptographic gadgets and for maintaining a clear correspondence between the code and the underlying theory.

## Project description

The architecture follows a hierarchical design pattern, separating data structures (Entities), cryptographic building blocks (Gadgets), and high-level protocols (Algorithms).
 
### Architecture Overview

The codebase is organized into four distinct layers, arranged from low-level data structures to high-level orchestration:

#### Entities `src/entities`

These are the fundamental data objects used throughout the system. They represent the state and mathematical structures required for the encryption scheme. These objects are passed as inputs and outputs between Gadgets and Algorithms.

#### Gadgets `src/gadgets`

These are the low-level cryptographic building blocks (based on linearly verifiable SNARKs). They implement specific logic used to construct proofs for the R-ABE relation.

- `iip.rs`: Indexed Inner Product gadget.
- `zero_check.rs`: Zero Check gadget.

Gadgets consume Entities to generate proofs or verify specific mathematical constraints.

#### Algorithms `src/algorithms` 

This layer implements the core R-ABE protocols defined in the research paper. These algorithms compose Gadgets and manipulate Entities to perform system operations.
- `setup`: Generates the global CRS.
- `kgen`: Generates individual user keys (pk, sk).
- `isValid`: This algorithm verifies that a registered public key was generated correctly with respect to the system CRS.
- `aggregate`: Compresses user keys into the MasterPublicKey and generates HelperDecryption keys.
- `encrypt` / `decrypt`: Handles the encryption of messages under a Policy and their recovery.

#### WE Framework `src/we.rs`

The Witness Encryption class serves as the high-level orchestrator for the entire lifecycle of the scheme. It ties the algorithms together to simulate a full system usage flow.

## R-ABE algorithms
This section details the implementation of the core R-ABE algorithms located in `src/algorithms`.

### Setup (`setup.rs`)

The `setup` algorithm initializes the system by generating the Common Reference String (CRS).
* **Implementation:** It samples a random secret $\tau \in \mathbb{F}_p$ and computes the "powers-of-tau" vectors.
* **Output:** A `CRS` entity consisting of two vectors of length $M$ (the maximum number of users), containing the powers of $\tau$ in both source groups $\mathbb{G}_1$ and $\mathbb{G}_2$:
    * $[\tau^0]_1, [\tau^1]_1, \dots, [\tau^M]_1$
    * $[\tau^0]_2, [\tau^1]_2, \dots, [\tau^M]_2$
* **Dependencies:** Uses `ark-ec` for group elements and `ark-ff` for finite field arithmetic.

### Key Generation (`kgen.rs`)

The `kgen` algorithm generates individual user keys.
* **Secret Key ($sk$):** A random scalar value sampled from the finite field $\mathbb{F}_p$.
* **Public Key ($pk$):** Generated using the `IIPGadget::aux_gen` method. It produces a vector of group elements in $\mathbb{G}_1$ that effectively "commit" to the secret key scaled by powers of $\tau$:
    * $pk = ([sk \cdot \tau^0]_1, [sk \cdot \tau^1]_1, \dots, [sk \cdot \tau^M]_1)$

### Key Verification (`is_valid.rs`)

The `is_valid` function allows the Aggregator (or any third party) to verify the well-formedness of a registered public key without knowing the secret key.
* **Implementation:** It checks the consistency of the public key elements using bilinear pairings. For each element $j$ in the public key vector, it verifies the relationship:
    $$e([sk]_1, [\tau^j]_2) = e([sk \cdot \tau^j]_1, [1]_2)$$
This ensures that the public key correctly corresponds to the underlying secret scalar $sk$ and the system's CRS.

### Aggregate (`aggregate.rs`)

The `aggregate` function compresses the individual public keys and attribute sets of all users into a succinct Master Public Key (MPK) and precomputes user-specific Helper Decryption Keys (HSK).

#### Workflow

* **Effective user attributes**: It identifies the set of "effective attributes" $\mathcal{U}_{eff}$ (all unique attributes).

* **User Partitioning**:For each attribute $u_j \in \mathcal{U}_{eff}$, the algorithm partitions users into two sets:
    * $\mathcal{I}_{u_j}^{(0)}$: The set of user indices $\{i\}$ who possess attribute $u_j$.
    * $\mathcal{I}_{u_j}^{(1)}$: The set of user indices $\{i\}$ who do not possess attribute $u_j$.

* **MPK Construction**:
    * **Attribute Commitment**s: It uses `ZeroCheckGadget::digest` to compute commitments to the vanishing polynomials for these sets.
        * u_list_0 corresponds to $U_j^{(0)} = [Z_{\mathcal{I}_{u_j}^{(0)}}(\tau)]_1$.
        * u_list_1 corresponds to $U_j^{(1)} = [Z_{\mathcal{I}_{u_j}^{(1)}}(\tau)]_1$.
    * *Key Commitment*: It uses `IIPGadget::digest` to compute the aggregated commitment to the vector of secret keys ($C$) and the domain vanishing polynomial ($U$).

* **HSK Generation**:
    * For each user $i$, it precomputes the proof components so the user doesn't have to perform these operations during decryption.
    * `ZeroCheckGadget::prove`: Computes the polynomial evaluations (hsk_0, hsk_1) proving the user's membership (or not) in the attribute sets.
    * `IIPGadget::prove`: Computes the five helper elements (hsk_n_1...hsk_n_5).

### Encrypt (`encrypt.rs`)

The `encrypt` transforms a DNF policy into a ciphertext.

A code specific optimization was the fact that instead of constructing the large, sparse matrix $A_\alpha$ explicitly (which would be inefficient in memory), this implementation performs the vector-matrix multiplication $s^\top \cdot A_\alpha$ on the go. It iterates through the conceptual columns of the result vector and accumulates only the non-zero terms defined in the paper.

While the research paper defines specific handling for attributes not in $\mathcal{U}_{eff}$, this prototype focuses on the active attribute set to simplify the logic.

#### Mathematical Mapping

For each clause in the policy with $k$ literals, the algorithm: 

* **Randomness Sampling:** Generates a random blinding vector $s \in \mathbb{F}_p^{k+2}$.

* **Column Construction ($i$ from $0$ to $k+3$)**:
    * Columns $0 \dots k-1$:
        * *Paper*: Diagonal entries $-Z_\Omega(\tau)$ in $\mathbb{G}_2$. 
        * *Code*: Computes c2_i = -mpk.u * s[i]. 
    * Column $k$:
        * *Paper*: This is the complex column containing attribute commitments $U_{i, \beta}$ and the key commitment $C$.
        * *Code*: This is the only column resulting in a $\mathbb{G}_1$ element. It computes the weighted sum of attribute commitments (sum_attr) and adds the key commitment term (mpk.c * s[k]).
        * *Logic*: This term ties the randomizers $s_j$ to the specific attributes required by the policy.
    * Column $k+1$:
        * *Paper*: Contains $-Z_\Omega(\tau)$ in row $k$.
        * *Code*: Computes c2_i = -mpk.u * s[k].
    * Columns $k+2, k+3$:
        * *Paper*: Handles the powers of $\tau$ to verify the degree of the quotient polynomial $Q_x$.
        * *Code*: Computes linear combinations of CRS elements (e.g., crs.g2_powers[1]) based on the last two elements of the vector $s$.
* **Blinding ($c_3$)**: Computes $s^\top b + msg$. Since $b = (1, 0, \dots, 0)^\top$, this simplifies to masking the message with the first element of $s$ paired with $[1]_T$, so c3 = crs.gt * s[0] + msg.

### Decrypt (`decrypt.rs`)

The `decrypt` algorithm recovers the message if the user's attributes satisfy the ciphertext's policy.

**Implementation**:

* **Proof Construction** `(PiUser::new)`: Before attempting decryption, the user constructs their personal proof vector $\pi$ (PiUser).

* **Clause Selection**: The algorithm iterates through the DNF policy $\mathcal{P} = \bigvee_{\alpha} \text{Clause}_\alpha$. It checks if the user's attributes_list satisfies the current clause.

* **Bilinear Pairing Recovery**: Once a satisfied clause is found, the algorithm computes the dot product of the ciphertext rows ($c_1, c_2$) with the proof vector $\pi$ using bilinear pairings.

* **Attribute Terms**: For each literal in the clause, it pairs the corresponding attribute proof $\pi_{attr}$ with the ciphertext element $c_2[j]$.sum += pairing(pi_attr, c2[j])

* **Identity & Key Terms**: It performs the fixed set of pairings for the IIP/DLOG check columns ($k \dots k+3$). The term $c_1[k]$ is paired with $\pi_{n+1}$. 

* **Message Extraction**: The final message is recovered by subtracting the computed sum from the blinded element $c_3$.$msg = c_3 - \text{sum}$

## Testing of the code

The codebase includes unit tests and internal verification to ensure the correctness of the cryptographic gadgets and aggregated keys.

#### Unit Tests `lib.rs`

Basic unit tests validate:

* Correct construction of entities (CRS, keys, commitments)
* Consistency of field and group operations
* Deterministic behavior where expected

#### Gadget Verification

The correctness of the aggregation phase is  verified using:

* `IIPGadget::verify`
* `ZeroCheckGadget::verify`

These checks ensure that:
* The Master Public Key (MPK) is consistent with the registered user keys
* The Helper Secret Keys (HSK) are correctly generated for each user
* The algebraic relations defined in the paper are satisfied

#### Notes on Equation-Level Modifications

Some minor algebraic adjustments were made compared to the equations in the paper to better align with implementation constraints and avoid type inconsistencies:

* Equations (1) to (k): 
    * These relations are implemented exactly as specified in the paper.

* Equation (k+1) 
    * A negative Lagrange polynomial evaluated at 0 is introduced
    * The explicit constant term [1] on the right-hand side is removed
    * The zero term is eliminated for consistency

* Equation (k+2)
    * The left-hand side uses $\tau^1$ instead of $\tau^2$

These modifications were mathematically verified and preserve correctness. They primarily address implementation-level type alignment rather than conceptual changes to the construction.
