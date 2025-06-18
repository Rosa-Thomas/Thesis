import * as mcl from "mcl-wasm";
import crypto from "crypto";
import { timeLockMessage } from "../tlock/tlock-wrapper.js"; 

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

class RealTLockWrapper {
  constructor(delaySeconds = 10) {
    this.delaySeconds = delaySeconds;
    this.encrypted = null;
  }

  async encrypt(message) {
    // Encrypt message with a real timelock, returns ciphertext string
    const ciphertext = await timeLockMessage(message, this.delaySeconds);
    this.encrypted = ciphertext; // Store ciphertext if needed
    return ciphertext;
  }

  async decrypt(ciphertext) {
    return ciphertext;
  }
}

class VotingSystem {
  constructor(tlock) {
    this.voters = new Map(); // voterId => { secretKey, publicKey }
    this.ballots = [];       // { electionId, ballot, proof }
    this.g = new mcl.G1();
    this.g.setHashOf("generator");
    this.tlock = tlock;
    this.encryptedTallies = new Map(); // electionId => encrypted result
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
      const [_, { publicKey }] = voterList[k];
      if (k < jIndex) gyj = mcl.add(gyj, publicKey);
      else if (k > jIndex) gyj = mcl.sub(gyj, publicKey);
    }

    return gyj;
  }

  castVote(voterId, vote, electionId) {
    if (!this.voters.has(voterId)) throw new Error(`Voter ${voterId} not registered`);
    if (![0, 1].includes(vote)) throw new Error("Only binary votes (0 or 1) supported");

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

    const r = new mcl.Fr();
    r.setByCSPRNG();
    const a = mcl.pow(pairing2, r);
    const c = hashToFr(pairing2, a, votePart);
    const s = mcl.sub(r, mcl.mul(c, voteFr));

    this.ballots.push({
      electionId,
      ballot,
      proof: {
        a,
        s,
        pairingBase: pairing2.serializeToHexStr(),
        votePartHex: votePart.serializeToHexStr(),
      },
    });

    console.log(`Ballot cast by ${voterId}`);
  }

  async tallyVotes(electionId, maxVotes = 10) {
    const ballots = this.ballots.filter(b => b.electionId === electionId);
    if (!ballots.length) {
      console.log("No ballots.");
      return;
    }

    const H = mcl.hashAndMapToG2(electionId);
    let R = new mcl.GT();
    R.setInt(1);
    const base = mcl.pairing(this.g, H);

    for (const { ballot, proof } of ballots) {
      const { a, s, pairingBase, votePartHex } = proof;

      const pairingBaseGT = new mcl.GT();
      pairingBaseGT.deserializeHexStr(pairingBase);
      const votePart = new mcl.GT();
      votePart.deserializeHexStr(votePartHex);

      const c = hashToFr(pairingBaseGT, a, votePart);
      const lhs = mcl.mul(mcl.pow(pairingBaseGT, s), mcl.pow(votePart, c));

      if (!lhs.isEqual(a)) {
        console.log("Invalid ballot proof — skipping");
        continue;
      }

      R = mcl.mul(R, ballot);
    }

    // Extract tally result
    let result = "Tally failed";
    for (let i = 0; i <= maxVotes; i++) {
      const exp = new mcl.Fr();
      exp.setInt(i);
      if (mcl.pow(base, exp).isEqual(R)) {
        result = i.toString();
        break;
      }
    }

    // Real TLock encryption (this will wait internally until unlock)
    const encryptedResult = await this.tlock.encrypt(result);
    this.encryptedTallies.set(electionId, encryptedResult);
    console.log(`Tally result for '${electionId}' encrypted (timelocked).`);
  }

  async revealTally(electionId) {
    const encrypted = this.encryptedTallies.get(electionId);
    if (!encrypted) {
      console.log("No tally found.");
      return;
    }

    try {
      // decrypt will just return the message since timeLockMessage waits and decrypts
      const decrypted = await this.tlock.decrypt(encrypted);
      console.log(`🗳️ Tally for '${electionId}': ${decrypted}`);
    } catch (e) {
      console.log(`❌ Decryption failed: ${e.message}`);
    }
  }
}

async function main() {
  await mcl.init(mcl.BLS12_381);
  mcl.setMapToMode(0);

  const tlock = new RealTLockWrapper(10); // 10 second delay
  const voteSys = new VotingSystem(tlock);

  ["Alice", "Bob", "Carol"].forEach(id => voteSys.registerVoter(id));

  voteSys.castVote("Alice", 1, "ElectionA");
  voteSys.castVote("Bob", 0, "ElectionA");
  voteSys.castVote("Carol", 1, "ElectionA");

  voteSys.castVote("Alice", 1, "ElectionB");
  voteSys.castVote("Bob", 1, "ElectionB");
  voteSys.castVote("Carol", 1, "ElectionB");

  await voteSys.tallyVotes("ElectionA");
  await voteSys.tallyVotes("ElectionB");

  await voteSys.revealTally("ElectionA");
  await voteSys.revealTally("ElectionB");
}

main();
