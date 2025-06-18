import fs from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";
import * as mcl from "mcl-wasm";
import crypto from "crypto";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function setupMCL() {
  await mcl.init(mcl.BLS12_381);
  mcl.setMapToMode(0);
}

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

class VotingSystem {
  constructor(tlockDelays = {}) {
    this.voters = new Map();
    this.ballots = new Map();
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
    await new Promise((res) => setTimeout(res, delay * 1000));
    for (let i = 0; i <= maxVotes; i++) {
      const fr = new mcl.Fr();
      fr.setInt(i);
      if (mcl.pow(base, fr).isEqual(R)) {
        return i;
      }
    }
    return "Tally Failed";
  }
}

async function simulateParallelElection({
  totalVoters = 100,
  groupSize = 10,
  missingProbability = 0.3,
  electionId = "Election2025/SimulatedParallel",
  maxVoteValue = 1,
  voteBias = 0.5
} = {}) {
  console.time(`Total Simulation Time for ${electionId}`);
  await setupMCL();

  const voterIDs = Array.from({ length: totalVoters }, (_, i) => `voter${i + 1}`);
  const groups = [];
  for (let i = 0; i < voterIDs.length; i += groupSize) {
    groups.push(voterIDs.slice(i, i + groupSize));
  }

  const groupTallyPromises = groups.map((groupVoters, groupIndex) => (async () => {
    let realGroupTally = 0;
    const tlockConfig = { [electionId]: 1 };
    const vs = new VotingSystem(tlockConfig);

    groupVoters.forEach(voterId => vs.registerVoter(voterId));

    groupVoters.forEach(voterId => {
      if (Math.random() < (1 - missingProbability)) {
        const vote = (Math.random() < voteBias) ? 1 : 0;
        realGroupTally += vote;
        vs.castVote(voterId, vote, electionId);
      }
    });

    const enc = await vs.encryptTally(electionId);
    const maxPossible = groupVoters.length * maxVoteValue;
    const groupTally = await vs.decryptTally(electionId, enc, maxPossible);

    const isFailed = typeof groupTally !== "number";
    const validGroupTally = isFailed ? 0 : groupTally;

    return {
      tally: validGroupTally,
      failed: isFailed,
      voterCount: groupVoters.length,
      realTally: realGroupTally
    };
  })());

  const groupResults = await Promise.all(groupTallyPromises);
  const globalTally = groupResults.reduce((sum, result) => sum + result.tally, 0);
  const realGlobalTally = groupResults.reduce((sum, result) => sum + result.realTally, 0);
  const totalGroups = groups.length;
  const failedCount = groupResults.filter(result => result.failed).length;
  const failedPercentage = (failedCount / totalGroups) * 100;

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

  let estimatedContribution = 0;
  groupResults.forEach(result => {
    if (result.failed) {
      estimatedContribution += result.voterCount * averageSuccessfulVote;
    }
  });

  const estimatedGlobalTally = globalTally + estimatedContribution;
  const errorPercentage = realGlobalTally > 0 ?
    (Math.abs(realGlobalTally - estimatedGlobalTally) / realGlobalTally) * 100 : 0;

  const outputPath = path.join(__dirname, "parallel_simulation_results_1.csv");

  if (!(await fs.stat(outputPath).catch(() => false))) {
    const header = [
      "electionId",
      "totalVoters",
      "numberOfGroups",
      "missingProbability",
      "voteBias",
      "realGlobalTally",
      "globalTally",
      "failedCount",
      "failedPercentage",
      "averageSuccessfulVote",
      "estimatedContribution",
      "estimatedGlobalTally",
      "errorPercentage"
    ];
    await fs.writeFile(outputPath, header.join(",") + "\n");
  }

  const csvRow = [
    electionId,
    totalVoters,
    totalGroups,
    missingProbability,
    voteBias,
    realGlobalTally,
    globalTally,
    failedCount,
    failedPercentage.toFixed(2),
    averageSuccessfulVote.toFixed(2),
    estimatedContribution.toFixed(2),
    estimatedGlobalTally.toFixed(2),
    errorPercentage.toFixed(2)
  ].join(",") + "\n";

  await fs.appendFile(outputPath, csvRow);
  console.timeEnd(`Total Simulation Time for ${electionId}`);
}

async function runMultipleSimulations(numRuns = 10) {
  let totalTime = 0;
  for (let i = 0; i < numRuns; i++) {
    const start = performance.now();
    await simulateParallelElection({
      totalVoters: 1000,
      groupSize: 5,
      missingProbability: 0.03,
      electionId: `Election_Run${i + 1}`,
      maxVoteValue: 1,
      voteBias: 0.7
    });
    const end = performance.now();
    totalTime += (end - start) / 1000;
  }
  console.log(`Average runtime: ${(totalTime / numRuns).toFixed(3)} seconds`);
}

runMultipleSimulations().catch(console.error);
