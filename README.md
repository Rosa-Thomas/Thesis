NivoteFileSystem & NivoteElection
This repository contains two JavaScript implementations of a cryptographic voting system using MCL (MIRACL Cryptographic Library) BLS12-381 pairing-based cryptography. While both scripts share fundamental cryptographic elements, they serve distinct purposes in vote encryption, tally computation, and simulation.

NivoteFileSystem.js
This script implements an individual election-based voting system using threshold encryption and time-lock decryption mechanisms. It provides functionalities such as:

Voter Registration: Each voter is assigned a secret-private key and a corresponding public key.

Vote Casting: Voters can submit encrypted ballots using pairing-based cryptography.

Fiat-Shamir Proof: Ensures vote integrity using zero-knowledge proofs.

Tally Encryption: Votes are aggregated into a single encrypted result.

Time-Locked Decryption: Tally results are only deciphered after a configured delay.

Usage
Place an input.json file in the same directory, specifying elections and voter choices.

Run the script, which registers voters, collects ballots, encrypts the tally, and performs delayed decryption.

The final tally is stored in results.json.

NivoteElection.js
This script extends the voting mechanism to simulate parallel elections across multiple voting groups with cryptographic aggregation. It introduces:

Parallel Vote Processing: Multiple voter groups cast votes independently, simulating real-world elections.

Voter Behavior Simulation: Voters have a probability of abstaining from voting.

Cryptographic Aggregation: Votes are verified and securely combined across groups.

Failure Recovery Estimation: If a vote decryption fails, an estimated tally is computed.

Usage
Configure election parameters such as voter count, group size, absentee probability, and vote bias.

Execute the script to simulate voting, compute encrypted tallies, and estimate global election results.

The simulation summary is saved in parallel_simulation_results.json.

Key Differences
Feature	NivoteFileSystem.js	NivoteElection.js
Scope	Single election tally	Simulated parallel voting
Tally Mechanism	Time-locked decryption	Cryptographic aggregation
Voting Method	Direct voting per election	Group-based voting simulation
Failure Handling	No tally estimation	Estimated tally recovery
Both implementations showcase privacy-preserving, verifiable voting using pairing-based cryptography.
