import * as mcl from "mcl-wasm";
import crypto from "crypto";
import { generateZKORProof, hashToFr } from "../ZKP/generateZKORProof.js";

// Initialize MCL
async function setupMCL() {
  await mcl.init(mcl.BLS12_381);
  mcl.setMapToMode(0);
  console.log("MCL Initialized");
}



class VotingSystem {
  constructor() {
    this.voters = new Map();
    this.ballots = [];
    this.castLog = new Map();
    this.g = new mcl.G1();
    this.g.setHashOf("generator");
  }

  registerVoter(voterId) {
    const sk = new mcl.Fr();
    sk.setByCSPRNG();
    const pk = mcl.mul(this.g, sk);
    this.voters.set(voterId, { secretKey: sk, publicKey: pk });
    console.log(`Voter registered: ${voterId}`);
    return pk.serializeToHexStr();
  }

  computeGyj(voterId) {
    const voterList = Array.from(this.voters.entries());
    const jIndex = voterList.findIndex(([id]) => id === voterId);

    let gyj = new mcl.G1();
    gyj.clear();

    for (let k = 0; k < voterList.length; k++) {
      const [, { publicKey }] = voterList[k];
      if (k < jIndex) {
        gyj = mcl.add(gyj, publicKey);
      } else if (k > jIndex) {
        gyj = mcl.sub(gyj, publicKey);
      }
    }

    return gyj;
  }


  castVote(voterId, vote, electionId) {
    if (!this.voters.has(voterId)) throw new Error(`Voter ${voterId} not registered`);
    if (vote !== 0 && vote !== 1) throw new Error("Only binary votes (0 or 1) are supported");

    const log = this.castLog.get(electionId) || new Set();
    if (log.has(voterId)) throw new Error(`${voterId} already voted in ${electionId}`);

    const { secretKey: sk } = this.voters.get(voterId);
    const gyj = this.computeGyj(voterId);
    const H = mcl.hashAndMapToG2(electionId);

    const pairing1 = mcl.pairing(gyj, H);
    const part1 = mcl.pow(pairing1, sk);

    const voteFr = new mcl.Fr();
    voteFr.setInt(vote);

    const pairing2 = mcl.pairing(this.g, H);
    const votePart = mcl.pow(pairing2, voteFr);

    const ballot = mcl.mul(part1, votePart);

    const B = pairing2;

    // Use wrapper to generate ZK OR-proof
    const proof = generateZKORProof(vote, B, votePart, electionId);

    this.ballots.push({
      electionId,
      ballot,
      proof: {
        a0: proof.a0.serializeToHexStr(),
        a1: proof.a1.serializeToHexStr(),
        c0: proof.c0.serializeToHexStr(),
        c1: proof.c1.serializeToHexStr(),
        s0: proof.s0.serializeToHexStr(),
        s1: proof.s1.serializeToHexStr(),
        pairingBase: B.serializeToHexStr(),
        votePartHex: votePart.serializeToHexStr(),
      },
    });

    log.add(voterId);
    this.castLog.set(electionId, log);

    console.log(`Ballot cast by ${voterId} with ZK OR-proof`);
  }

  tallyVotes(electionId, maxVotes = 10) {
    const ballotsForElection = this.ballots.filter(b => b.electionId === electionId);

    if (ballotsForElection.length === 0) {
      console.log("No ballots cast.");
      return;
    }

    const H = mcl.hashAndMapToG2(electionId);
    let R = new mcl.GT();
    R.setInt(1);

    for (const { ballot, proof } of ballotsForElection) {
      const base = new mcl.GT();
      base.deserializeHexStr(proof.pairingBase);

      const votePart = new mcl.GT();
      votePart.deserializeHexStr(proof.votePartHex);

      const a0 = new mcl.GT();
      a0.deserializeHexStr(proof.a0);

      const a1 = new mcl.GT();
      a1.deserializeHexStr(proof.a1);

      const c0 = new mcl.Fr();
      const c1 = new mcl.Fr();
      const s0 = new mcl.Fr();
      const s1 = new mcl.Fr();

      c0.deserializeHexStr(proof.c0);
      c1.deserializeHexStr(proof.c1);
      s0.deserializeHexStr(proof.s0);
      s1.deserializeHexStr(proof.s1);

      // Verification equations for OR proof
      const lhs0 = mcl.mul(mcl.pow(base, s0), mcl.pow(votePart, c0)); // For vote=0
      const lhs1 = mcl.mul(mcl.pow(base, s1), mcl.pow(base, c1));     // For vote=1

      const c = hashToFr(base, a0, a1, votePart, electionId);

      if (!a0.isEqual(lhs0) || !a1.isEqual(lhs1) || !c.isEqual(mcl.add(c0, c1))) {
        console.log("Invalid ballot proof — skipping");
        continue;
      }

      R = mcl.mul(R, ballot);
    }

    const base = mcl.pairing(this.g, H);
    let tally = null;
    for (let i = 0; i <= maxVotes; i++) {
      const exp = new mcl.Fr();
      exp.setInt(i);
      if (mcl.pow(base, exp).isEqual(R)) {
        tally = i;
        break;
      }
    }

    console.log("Election Result:", tally !== null ? tally : "Tally failed");
  }
}

async function main() {
  await setupMCL();
  const voteSystem = new VotingSystem();

  voteSystem.registerVoter("Tom");
  voteSystem.registerVoter("John");
  voteSystem.registerVoter("Sarah");

  voteSystem.castVote("Tom", 0, "Election2025/01");
  voteSystem.castVote("John", 1, "Election2025/01");
  voteSystem.castVote("Sarah", 1, "Election2025/01");

  voteSystem.tallyVotes("Election2025/01");

  voteSystem.castVote("Tom", 0, "Election2025/02");
  voteSystem.castVote("John", 1, "Election2025/02");
  voteSystem.castVote("Sarah", 0, "Election2025/02");

  voteSystem.tallyVotes("Election2025/02");
}

main();
