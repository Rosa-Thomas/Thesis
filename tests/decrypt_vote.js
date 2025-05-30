const crypto = require("crypto");

const encrypted = process.argv[2];
const keyHex = process.argv[3];
const ivHex = process.argv[4];

const key = Buffer.from(keyHex, "hex");
const iv = Buffer.from(ivHex, "hex");

const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
let decrypted = decipher.update(encrypted, "hex", "utf8");
decrypted += decipher.final("utf8");

console.log("Decrypted:", decrypted);
