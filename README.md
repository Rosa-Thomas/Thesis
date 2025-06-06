Nivote Voting System
This repository contains two JavaScript implementations of a cryptographic voting system using MCL (MIRACL Cryptographic Library) BLS12-381 pairing-based cryptography. Both scripts are located in the Nivote folder and provide secure, verifiable voting methods with encryption and tally computation.

How to Use the Scripts
1. NivoteFileSystem.js (Standard Election Voting)
This script is designed for single elections, handling voter registration, vote encryption, and time-locked tally decryption.

Setup & Execution
Ensure you have Node.js installed.

Navigate to the Nivote folder.

Create an input.json file that specifies election details and voter choices.

Run the script:

sh
node NivoteFileSystem.js
The encrypted tally result will be stored in results.json.

2. NivoteElection.js (Parallel Election Simulation)
This script extends the system to simulate multiple voting groups, processing votes concurrently and estimating tallies if failures occur.

Setup & Execution
Ensure you have Node.js installed.

Navigate to the Nivote folder.

Configure election parameters (such as voter count, group size, and absentee probability) directly in the script.

Run the script:

sh
node NivoteElection.js
The simulation results, including estimated tallies, will be saved in parallel_simulation_results.json.

Key Differences Between the Two Scripts
Feature	NivoteFileSystem.js	NivoteElection.js
Scope	Handles a single election tally	Simulates multiple voting groups
Tally Mechanism	Time-locked decryption	Cryptographic aggregation across groups
Voting Method	Direct voting per election	Group-based voting simulation
Failure Handling	No tally estimation	Estimated tally recovery
Both implementations showcase privacy-preserving, verifiable voting using pairing-based cryptography, ensuring integrity and reliability in election systems.
