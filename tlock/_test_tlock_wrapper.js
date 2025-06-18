import { timeLockMessage } from './tlock-wrapper.js';

async function main() {
  const secret = "###_hashed_code_###";
  const delaySeconds = 3;

  console.log("Starting time-lock...");
  const revealed = await timeLockMessage(secret, delaySeconds);
  console.log("Decrypted after time-lock:", revealed);
}

main().catch(console.error);
