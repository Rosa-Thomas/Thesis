const crypto = require("crypto");
const message = process.argv[2] || "default vote";

const key = crypto.randomBytes(32);
const iv = crypto.randomBytes(16);

const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
let encrypted = cipher.update(message, "utf8", "hex");
encrypted += cipher.final("hex");

console.log("Encrypted:", encrypted);
console.log("Key:", key.toString("hex"));
console.log("IV:", iv.toString("hex"));
