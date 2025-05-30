import fs from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";
import * as mcl from "mcl-wasm";
import crypto from "crypto";

// File path helpers
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Setup MCL
async function setupMCL() {
  await mcl.init(mcl.BLS12_381);
  mcl.setMapToMode(0);
}

// Deterministic Fiat-Shamir hash → Fr
function hashToFr(...elements) {
  const hash = crypto.createHash("sha256");
  for (const el of elements) {
    if (typeof el.serialize === "function") {
      hash.update(el.serialize());
    } else if (typeof el.serializeToHexStr === "function") {
      hash.update(Buffer.from(el.serializeToHexStr(), "hex"));
    } else if (Buffer.isBuffer(el)) {
      hash.update(el);
    } else {
      throw new Error("Unsupported element for hashing");
    }
  }
  const digest = hash.digest();
  const fr = new mcl.Fr();
  fr.setHashOf(digest);
  return fr;
}

// VotingSystem class encapsulates voter registration, vote casting (with a Fiat-Shamir proof),
// encryption of ballots, and decryption (via a discrete logarithm search after a time-lock delay).
class VotingSystem {
  constructor(tlockDelays = {}) {
    this.voters = new Map();
    this.ballots = new Map(); // electionId => [ { ballot, proof } ]
    this.g = new mcl.G1();
    this.g.setHashOf("generator");
    this.tlockDelays = tlockDelays;
  }

  registerVoter(voterId) {
    const sk = new mcl.Fr();
    sk.setByCSPRNG();
    const pk = mcl.mul(this.g, sk);
    this.voters.set(voterId, { sk, pk });
  }

  computeGyj(voterId) {
    const voterList = Array.from(this.voters.entries());
    const jIndex = voterList.findIndex(([id]) => id === voterId);
    let gyj = new mcl.G1();
    gyj.clear();
    for (let k = 0; k < voterList.length; k++) {
      const [_, { pk }] = voterList[k];
      if (k < jIndex) {
        gyj = mcl.add(gyj, pk);
      } else if (k > jIndex) {
        gyj = mcl.sub(gyj, pk);
      }
    }
    return gyj;
  }

  castVote(voterId, vote, electionId) {
    const { sk } = this.voters.get(voterId);
    const gyj = this.computeGyj(voterId);
    const H = mcl.hashAndMapToG2(electionId);

    const pairing1 = mcl.pairing(gyj, H);
    const part1 = mcl.pow(pairing1, sk);

    const voteFr = new mcl.Fr();
    voteFr.setInt(vote);
    const pairing2 = mcl.pairing(this.g, H);
    const votePart = mcl.pow(pairing2, voteFr);
    const ballot = mcl.mul(part1, votePart);

    // Create Fiat-Shamir proof for the vote.
    const r = new mcl.Fr();
    r.setByCSPRNG();
    const a = mcl.pow(pairing2, r);
    const c = hashToFr(pairing2, a, votePart);
    const s = mcl.sub(r, mcl.mul(c, voteFr));

    if (!this.ballots.has(electionId)) {
      this.ballots.set(electionId, []);
    }
    this.ballots.get(electionId).push({
      ballot,
      proof: {
        a,
        s,
        pairingBase: pairing2.serializeToHexStr(),
        votePartHex: votePart.serializeToHexStr()
      }
    });
  }

  async encryptTally(electionId) {
    const H = mcl.hashAndMapToG2(electionId);
    const base = mcl.pairing(this.g, H);
    let R = new mcl.GT();
    R.setInt(1);
    const entries = this.ballots.get(electionId) || [];
    for (const { ballot, proof } of entries) {
      const { a, s, pairingBase, votePartHex } = proof;
      const pairing2 = new mcl.GT();
      pairing2.deserializeHexStr(pairingBase);
      const votePart = new mcl.GT();
      votePart.deserializeHexStr(votePartHex);
      const c = hashToFr(pairing2, a, votePart);
      const lhs = mcl.mul(mcl.pow(pairing2, s), mcl.pow(votePart, c));
      if (lhs.isEqual(a)) {
        R = mcl.mul(R, ballot);
      }
    }
    return { R, base };
  }

  async decryptTally(electionId, { R, base }, maxVotes = 10) {
    const delay = this.tlockDelays[electionId] ?? 1;
    console.log(`Waiting ${delay}s for tally of ${electionId}...`);
    await new Promise((res) => setTimeout(res, delay * 1000));
    console.log(`Starting discrete log search up to maxVotes=${maxVotes}`);
    for (let i = 0; i <= maxVotes; i++) {
      const fr = new mcl.Fr();
      fr.setInt(i);
      if (mcl.pow(base, fr).isEqual(R)) {
        console.log(`Match found! Tally = ${i}`);
        return i;
      }
    }
    console.log("No matching tally found — Tally Failed");
    return "Tally Failed";
  }
}

// -----------------------------
// Simulation: Parallelized Tally Per Group with Estimated Votes Compared to Real Tally
// -----------------------------
//
// This simulation divides voters into groups and processes each group's votes concurrently.
// For each active voter, a vote is generated as follows: the voter casts a 1 with probability voteBias, and 0 otherwise.
// The "real" tally is simply the sum of generated votes for a group.
// Separately, each group performs encryption/decryption which may fail;
// if decryption fails, the group's cryptographic tally is set to 0.
// We then compute the average successful vote per voter from groups that succeeded;
// for each failed group we estimate its contribution as:
//        (number of voters in the group) × (average successful vote per voter)
// Finally, the result file (written to disk) includes only aggregated information, including the percentage error
// between the real global tally and the estimated global tally.
async function simulateParallelElection({
  totalVoters = 100,
  groupSize = 10,
  missingProbability = 0.3,   // Probability that a voter does NOT vote
  electionId = "Election2025/SimulatedParallel",
  maxVoteValue = 1,
  voteBias = 0.5             // Probability an active voter votes 1 (for binary votes)
} = {}) {
  await setupMCL();

  // Create an array of voter IDs.
  const voterIDs = [];
  for (let i = 1; i <= totalVoters; i++) {
    voterIDs.push(`voter${i}`);
  }

  // Divide voters into groups.
  const groups = [];
  for (let i = 0; i < voterIDs.length; i += groupSize) {
    groups.push(voterIDs.slice(i, i + groupSize));
  }
  console.log(
    `Simulating election "${electionId}" with ${totalVoters} voters divided into ${groups.length} groups.`
  );

  // Process each group concurrently.
  const groupTallyPromises = groups.map((groupVoters, groupIndex) => (async () => {
    let realGroupTally = 0; // Real tally: sum of votes generated for active voters.
    const tlockConfig = { [electionId]: 1 }; // tlock delay of 1 second (simulation)
    const vs = new VotingSystem(tlockConfig);

    // Register all voters in this group.
    groupVoters.forEach(voterId => vs.registerVoter(voterId));

    // Each voter casts a vote (if not absent).
    groupVoters.forEach(voterId => {
      if (Math.random() < (1 - missingProbability)) {
        // Generate vote: active voter casts 1 with probability voteBias, or 0.
        const vote = (Math.random() < voteBias) ? 1 : 0;
        realGroupTally += vote;
        vs.castVote(voterId, vote, electionId);
        console.log(`Group ${groupIndex + 1}: Voter ${voterId} votes ${vote}`);
      } else {
        console.log(`Group ${groupIndex + 1}: Voter ${voterId} is absent.`);
      }
    });

    // Encrypt and then attempt decryption.
    const enc = await vs.encryptTally(electionId);
    const maxPossible = groupVoters.length * maxVoteValue;
    const groupTally = await vs.decryptTally(electionId, enc, maxPossible);

    const isFailed = typeof groupTally !== "number";
    const validGroupTally = isFailed ? 0 : groupTally;
    console.log(`Group ${groupIndex + 1} tally: ${validGroupTally} ${isFailed ? "(FAILED)" : ""}`);

    return {
      tally: validGroupTally,      // Tally from cryptographic process (0 if decryption failed)
      failed: isFailed,
      voterCount: groupVoters.length,
      realTally: realGroupTally   // The true sum of votes cast in the group
    };
  })());

  // Wait for all groups to finish.
  const groupResults = await Promise.all(groupTallyPromises);

  // Compute aggregated values.
  const globalTally = groupResults.reduce((sum, result) => sum + result.tally, 0);
  const realGlobalTally = groupResults.reduce((sum, result) => sum + result.realTally, 0);
  const totalGroups = groups.length;
  const failedCount = groupResults.filter(result => result.failed).length;
  const failedPercentage = totalGroups === 0 ? 0 : (failedCount / totalGroups) * 100;

  // Compute average successful vote per voter from groups that succeeded.
  let successfulVoteSum = 0;
  let successfulVoterCount = 0;
  groupResults.forEach(result => {
    if (!result.failed) {
      successfulVoteSum += result.tally;
      successfulVoterCount += result.voterCount;
    }
  });
  const averageSuccessfulVote = successfulVoterCount > 0 ?
    successfulVoteSum / successfulVoterCount : maxVoteValue / 2;

  // For each failed group, estimate its contribution using the average from successful groups.
  let estimatedContribution = 0;
  groupResults.forEach(result => {
    if (result.failed) {
      estimatedContribution += result.voterCount * averageSuccessfulVote;
    }
  });

  const estimatedGlobalTally = globalTally + estimatedContribution;

  // Compute percentage error between real global tally and estimated global tally.
  let errorPercentage = 0;
  if (realGlobalTally > 0) {
    errorPercentage = (Math.abs(realGlobalTally - estimatedGlobalTally) / realGlobalTally) * 100;
  }

  // Write a summary of the important aggregated information to a file.
  const results = {
    electionId,
    totalVoters,
    numberOfGroups: totalGroups,
    missingProbability,
    voteBias,
    realGlobalTally,               // The true sum of votes cast
    globalTally,                   // Sum from groups with successful decryption
    failedCount,
    failedPercentage: failedPercentage.toFixed(2) + "%",
    averageSuccessfulVote: averageSuccessfulVote.toFixed(2),
    estimatedContribution: estimatedContribution.toFixed(2),
    estimatedGlobalTally: estimatedGlobalTally.toFixed(2),
    errorPercentage: errorPercentage.toFixed(2) + "%"
  };

  const outputPath = path.join(__dirname, "parallel_simulation_results.json");
  await fs.writeFile(outputPath, JSON.stringify(results, null, 2));
  console.log(`Simulation complete. Results stored in ${outputPath}`);
}

// Kick off the simulation.
// Adjust voteBias to control the probability an active voter casts a 1.
simulateParallelElection({
  totalVoters: 1000,
  groupSize: 5,
  missingProbability: 0.1,
  electionId: "Election2025/SimulatedParallel",
  maxVoteValue: 1,
  voteBias: 0.5
}).catch(console.error);
