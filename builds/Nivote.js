import * as mcl from "mcl-wasm";

async function setupMCL() {
    await mcl.init(mcl.BLS12_381);
    mcl.setMapToMode(0); // Proper G2 hashing
    console.log("MCL Initialized");
}

class VotingSystem {
    constructor() {
        this.voters = new Map();     // voterId => { secretKey, publicKey }
        this.ballots = [];           // array of GT elements
        this.g = new mcl.G1();       // generator of G1
        this.g.setHashOf("generator");
    }

    registerVoter(voterId) {
        const sk = new mcl.Fr();
        sk.setByCSPRNG();
        const pk = mcl.mul(this.g, sk); // g^sk
        this.voters.set(voterId, { secretKey: sk, publicKey: pk }); // keep raw object
        console.log(`Voter registered: ${voterId}`);
        return pk.serializeToHexStr(); // return string if needed, but keep object internally
    }

    computeGyj(voterId) {
        const voterList = Array.from(this.voters.entries());
        const jIndex = voterList.findIndex(([id]) => id === voterId);

        let gyj = new mcl.G1();
        gyj.clear(); // Identity

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
        const H = mcl.hashAndMapToG2(electionId); // Hash to G2

        const pairing1 = mcl.pairing(gyj, H);          // e(gyj, H)
        const part1 = mcl.pow(pairing1, sk);           // e(gyj, H)^xj

        const voteFr = new mcl.Fr();
        voteFr.setInt(vote);

        const pairing2 = mcl.pairing(this.g, H);       // e(g, H)
        const part2 = mcl.pow(pairing2, voteFr);       // e(g, H)^v

        const ballot = mcl.mul(part1, part2);          // Final ballot
        this.ballots.push(ballot);

        console.log(`Ballot cast by ${voterId}: ${ballot.serializeToHexStr()}`);
    }

    tallyVotes(electionId, maxVotes = 10) {
        if (this.ballots.length === 0) {
            console.log("No ballots cast.");
            return;
        }

        // Aggregate ballots in GT
        let R = new mcl.GT();
        R.setInt(1); // identity
        for (const ballot of this.ballots) {
            R = mcl.mul(R, ballot);
        }

        const H = mcl.hashAndMapToG2(electionId);
        const base = mcl.pairing(this.g, H);

        // Brute-force search for tally value
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

    voteSystem.castVote("Tom", 0, "Election2025");
    voteSystem.castVote("John", 1, "Election2025");
    voteSystem.castVote("Sarah", 1, "Election2025");

    voteSystem.tallyVotes("Election2025");
}

main();
