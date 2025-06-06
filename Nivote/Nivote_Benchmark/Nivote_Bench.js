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
  constructor() {
    this.voters = new Map();
    this.ballots = new Map();
    this.g = new mcl.G1();
    this.g.setHashOf("generator");
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

  async decryptTally(enc, maxVotes = 10) {
    const { R, base } = enc;
    for (let i = 0; i <= maxVotes; i++) {
      const fr = new mcl.Fr();
      fr.setInt(i);
      if (mcl.pow(base, fr).isEqual(R)) {
        return i;
      }
    }
    return "Failed";
  }
}

// Helper to check if file exists
async function fileExists(filepath) {
  try {
    await fs.access(filepath);
    return true;
  } catch {
    return false;
  }
}

async function benchmarkEncryptionDecryption({
  totalVoters = 20,
  groupSize = 5,
  numRuns = 5,
  voteBias = 0.5,
  maxVoteValue = 1,
  missingProofRate = 0.0
} = {}) {
  await setupMCL();

  const voterIDs = [];
  for (let i = 1; i <= totalVoters; i++) {
    voterIDs.push(`voter${i}`);
  }

  const groups = [];
  for (let i = 0; i < voterIDs.length; i += groupSize) {
    groups.push(voterIDs.slice(i, i + groupSize));
  }

  const results = [];

  for (let run = 1; run <= numRuns; run++) {
    console.log(`Starting run ${run}/${numRuns}`);

    let totalEncTime = 0;
    let totalDecTime = 0;

    for (let g = 0; g < groups.length; g++) {
      const group = groups[g];
      const electionId = `Run${run}_Group${g + 1}`;

      const vs = new VotingSystem();
      group.forEach((voterId) => vs.registerVoter(voterId));

      group.forEach((voterId) => {
        if (Math.random() > missingProofRate) {
          const vote = Math.random() < voteBias ? 1 : 0;
          vs.castVote(voterId, vote, electionId);
        }
      });

      const encStart = performance.now();
      const enc = await vs.encryptTally(electionId);
      const encEnd = performance.now();

      const decStart = performance.now();
      const tally = await vs.decryptTally(enc, group.length * maxVoteValue);
      const decEnd = performance.now();

      const encTime = encEnd - encStart;
      const decTime = decEnd - decStart;

      totalEncTime += encTime;
      totalDecTime += decTime;

      results.push({
        run,
        totalVoters,
        groupSize,
        missingProofRate,
        voteBias,
        group: g + 1,
        encTimeMs: encTime.toFixed(3),
        decTimeMs: decTime.toFixed(3),
        tally,
      });

      console.log(
        `Run ${run} Group ${g + 1} - Encryption: ${encTime.toFixed(
          3
        )} ms, Decryption: ${decTime.toFixed(3)} ms, Tally: ${tally}`
      );
    }

    console.log(
      `Run ${run} summary: Avg Encryption Time: ${(totalEncTime / groups.length).toFixed(
        3
      )} ms, Avg Decryption Time: ${(totalDecTime / groups.length).toFixed(3)} ms`
    );
  }

  // Prepare CSV output with the requested columns
  const csvHeader = "Run,TotalVoters,GroupSize,MissingProofRate,VoteBias,Group,EncryptionTime(ms),DecryptionTime(ms),Tally\n";
  const csvLines = results.map(r =>
    `${r.run},${r.totalVoters},${r.groupSize},${r.missingProofRate},${r.voteBias},${r.group},${r.encTimeMs},${r.decTimeMs},${r.tally}`
  );

  const outPath = path.join(__dirname, "benchmark_results_g20.csv");
  const exists = await fileExists(outPath);

  if (!exists) {
    await fs.writeFile(outPath, csvHeader + csvLines.join("\n") + "\n", "utf-8");
  } else {
    await fs.appendFile(outPath, csvLines.join("\n") + "\n", "utf-8");
  }

  console.log(`Benchmark results saved to ${outPath}`);
}

benchmarkEncryptionDecryption({
  totalVoters: 2000,
  groupSize: 10,
  numRuns: 1,
  voteBias: 0.7,
  maxVoteValue: 1,
  missingProofRate: 0.05,
}).catch(console.error);
