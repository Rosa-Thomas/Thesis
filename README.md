# 🗳️ Nivote Voting System

**Nivote** is a collection of JavaScript-based cryptographic voting tools leveraging **BLS12-381 pairing-based cryptography** via `mcl-wasm`. It demonstrates privacy-preserving, verifiable voting with features such as time-locked tallies, group-based simulations, and performance benchmarking.

---

## 📁 Project Structure

All relevant and functional code is located in the `Nivote/` folder:

```
Nivote/
├── Nivote_Benchmark/          # Benchmarking encryption/decryption performance
├── Nivote_Simple/             # Basic voting system (input/output in JSON)
├── Nivote_Test_Election/      # Simulates multiple parallel elections
```

---

## 🔧 Requirements

- Node.js (v14+ recommended)
- Internet connection (for `mcl-wasm` initialization)

Install dependencies:
```bash
npm install
```

---

## 🧪 Script Overview

### ✅ `Nivote_Simple/`

A straightforward, single-election voting script.

- **Input**: `Nivote_Simple/input.json`
- **Output**: `Nivote_Simple/results.json`
- **Purpose**: Run a basic election, process encrypted votes, and output final tallies.

**Run it with:**
```bash
node Nivote_Simple/NivoteFileSystem.js
```

---

### 📊 `Nivote_Benchmark/`

Benchmarks encryption and decryption times over multiple runs.

- **Output**: CSV file (e.g., `benchmark_results_<timestamp>.csv`)
- **Purpose**: Analyze cryptographic performance (encryption/decryption time)

> ⚠️ **Note**: Output file will be overwritten unless you rename it in the script.

**Run it with:**
```bash
node Nivote_Benchmark/NivoteElection.js
```

---

### 🧩 `Nivote_Test_Election/`

Simulates multiple parallel elections with different voter groups.

- **Output**: CSV file (e.g., `test_simulation_results.csv`)
- **Purpose**: Test robustness under missing proofs and estimate tally error margins

> ⚠️ **Note**: The output CSV will be overwritten unless renamed in code.

**Run it with:**
```bash
node Nivote_Test_Election/Nivote_Test_Election.js
```

---

## 📌 Notes

- Only files inside the `Nivote/` folder are important; other files are utility/stub code.
- Rename CSV output files manually before running new simulations if you want to retain past data.
- Uses `mcl-wasm` for BLS12-381 pairing operations and zero-knowledge proof constructions.

---

## 📤 Outputs Summary

| Folder                 | Input File                    | Output File                              | Format |
|------------------------|-------------------------------|-------------------------------------------|--------|
| `Nivote_Simple`        | `input.json`                  | `results.json`                            | JSON   |
| `Nivote_Benchmark`     | Hardcoded inside script       | `benchmark_results_<timestamp>.csv`       | CSV    |
| `Nivote_Test_Election` | Hardcoded inside script       | `test_simulation_results.csv`             | CSV    |

---

## 💡 Future Improvements

- Optional CLI input for filenames and parameters
- Automatic archiving of CSV results
- More detailed zero-knowledge proof failure analysis