import * as mcl from "mcl-wasm";
import crypto from "crypto";

// Hash multiple elements into a scalar Fr
export function hashToFr(...elements) {
  const hash = crypto.createHash("sha256");
  for (const el of elements) {
    if (!el) throw new Error("Null or undefined element passed to hashToFr");
    if (typeof el.serialize === "function") {
      hash.update(el.serialize());
    } else if (typeof el.serializeToHexStr === "function") {
      hash.update(Buffer.from(el.serializeToHexStr(), "hex"));
    } else if (Buffer.isBuffer(el)) {
      hash.update(el);
    } else if (typeof el === "string") {
      hash.update(Buffer.from(el, "utf8"));
    } else {
      throw new Error("Unsupported element type for hashing");
    }
  }
  const digest = hash.digest();
  const fr = new mcl.Fr();
  fr.setHashOf(digest);
  return fr;
}

/**
 * Generate a zero-knowledge OR proof for vote ∈ {0,1}
 * @param {number} vote - 0 or 1
 * @param {mcl.GT} base - The base pairing element (e.g., e(g,H))
 * @param {mcl.GT} votePart - The vote exponentiation part (base^vote)
 * @param {string} electionId - For domain separation in the hash
 * @returns {object} proof with {a0, a1, c0, c1, s0, s1}
 */
export function generateZKORProof(vote, base, votePart, electionId) {
  if (vote !== 0 && vote !== 1) {
    throw new Error("Vote must be 0 or 1");
  }

  let c0 = new mcl.Fr();
  let c1 = new mcl.Fr();
  let s0 = new mcl.Fr();
  let s1 = new mcl.Fr();
  let a0, a1;

  const voteFr = new mcl.Fr();
  voteFr.setInt(vote);

  if (vote === 0) {
    // Simulate proof for vote=1 side
    c1.setByCSPRNG();
    s1.setByCSPRNG();
    a1 = mcl.mul(mcl.pow(base, s1), mcl.pow(base, c1));

    // Real proof for vote=0 side
    const r0 = new mcl.Fr();
    r0.setByCSPRNG();
    a0 = mcl.pow(base, r0);

    const c = hashToFr(base, a0, a1, votePart, electionId);
    c0 = mcl.sub(c, c1);
    s0 = mcl.sub(r0, mcl.mul(c0, voteFr));
  } else {
    // Simulate proof for vote=0 side
    c0.setByCSPRNG();
    s0.setByCSPRNG();
    a0 = mcl.mul(mcl.pow(base, s0), mcl.pow(votePart, c0));

    // Real proof for vote=1 side
    const r1 = new mcl.Fr();
    r1.setByCSPRNG();
    a1 = mcl.pow(base, r1);

    const c = hashToFr(base, a0, a1, votePart, electionId);
    c1 = mcl.sub(c, c0);
    s1 = mcl.sub(r1, mcl.mul(c1, voteFr));
  }

  return { a0, a1, c0, c1, s0, s1 };
}
