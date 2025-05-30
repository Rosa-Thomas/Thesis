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
      if (k < jIndex) gyj = mcl.add(gyj, pk);
      else if (k > jIndex) gyj = mcl.sub(gyj, pk);
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

    if (!this.ballots.has(electionId)) this.ballots.set(electionId, []);
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
      const pairing2 = new mcl.GT(); pairing2.deserializeHexStr(pairingBase);
      const votePart = new mcl.GT(); votePart.deserializeHexStr(votePartHex);
      const c = hashToFr(pairing2, a, votePart);
      const lhs = mcl.mul(mcl.pow(pairing2, s), mcl.pow(votePart, c));
      if (lhs.isEqual(a)) R = mcl.mul(R, ballot);
    }

    return { R, base };
  }

  async decryptTally(electionId, { R, base }, maxVotes = 10) {
    const delay = this.tlockDelays[electionId] ?? 5;
    console.log(`Waiting ${delay}s for tally of ${electionId}...`);
    await new Promise(res => setTimeout(res, delay * 1000));

    console.log(`Starting discrete log search up to maxVotes = ${maxVotes}`);

    for (let i = 0; i <= maxVotes; i++) {
      const fr = new mcl.Fr();
      fr.setInt(i);
      if (mcl.pow(base, fr).isEqual(R)) {
        console.log(`Match found! tally = ${i}`);
        return i;
      }
    }

    console.log("No matching tally found — Tally Failed");
    return "Tally Failed";
  }
}

// Main
async function main() {
  await setupMCL();

  const inputPath = path.join(__dirname, "input.json");
  const outputPath = path.join(__dirname, "results.json");

  const data = JSON.parse(await fs.readFile(inputPath, "utf8"));

  const tlockConfig = {
    "Election2025/01": 5,
    "Election2025/02": 10,
    "Election2025/03": 3,
    "Election2025/04": 7
  };

  const vs = new VotingSystem(tlockConfig);

  const voterSet = new Set();
  data.elections.forEach(e => e.votes.forEach(v => voterSet.add(v.voterId)));
  voterSet.forEach(id => vs.registerVoter(id));

  const results = [];

  for (const { id: electionId, votes } of data.elections) {
    votes.forEach(({ voterId, vote }) => vs.castVote(voterId, vote, electionId));
    const enc = await vs.encryptTally(electionId);
    const tally = await vs.decryptTally(electionId, enc, 5);
    results.push({ electionId, tally });
  }

  await fs.writeFile(outputPath, JSON.stringify(results, null, 2));
  console.log("Tally complete. See results.json");
}

main().catch(console.error);
