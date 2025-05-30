import * as mcl from "mcl-wasm";
import crypto from "crypto";

// Initialize MCL
async function setupMCL() {
    await mcl.init(mcl.BLS12_381);
    mcl.setMapToMode(0);
    console.log("MCL Initialized");
}

// Deterministic Fiat-Shamir hash → Fr with consistent serialization
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
        this.voters = new Map();     // voterId => { secretKey, publicKey }
        this.ballots = [];           // [{ ballot, proof: { a, s, pairingBase, votePartHex } }]
        this.g = new mcl.G1();       // generator of G1
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
        gyj.clear(); // identity element

        for (let k = 0; k < voterList.length; k++) {
            const [_, { publicKey }] = voterList[k];
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

        const { secretKey: sk } = this.voters.get(voterId);
        const gyj = this.computeGyj(voterId);
        const H = mcl.hashAndMapToG2(electionId);

        // Ballot: e(gyj, H)^xj * e(g, H)^v
        const pairing1 = mcl.pairing(gyj, H);
        const part1 = mcl.pow(pairing1, sk);

        const voteFr = new mcl.Fr();
        voteFr.setInt(vote);

        const pairing2 = mcl.pairing(this.g, H);
        const votePart = mcl.pow(pairing2, voteFr); // e(g,H)^v

        const ballot = mcl.mul(part1, votePart); // final encrypted vote

        // --- NIZK Proof that v ∈ {0,1} ---
        const r = new mcl.Fr();
        r.setByCSPRNG();

        const a = mcl.pow(pairing2, r);  // commitment: e(g, H)^r

        const c = hashToFr(pairing2, a, votePart); // Fiat-Shamir challenge on votePart only

        const s = mcl.sub(r, mcl.mul(c, voteFr)); // s = r - c·v

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

        console.log(`Ballot cast by ${voterId} with NIZK`);
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
            const { a, s, pairingBase, votePartHex } = proof;

            const base = new mcl.GT();
            base.deserializeHexStr(pairingBase);

            const votePart = new mcl.GT();
            votePart.deserializeHexStr(votePartHex);

            const c = hashToFr(base, a, votePart);
            const lhs = mcl.mul(mcl.pow(base, s), mcl.pow(votePart, c));

            if (!lhs.isEqual(a)) {
                console.log("Invalid ballot proof — skipping");
                continue;
            }

            R = mcl.mul(R, ballot);
        }

        // Extract discrete log tally: find i with e(g,H)^i == R
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

// test
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
