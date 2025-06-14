import { quicknet } from './client-utils.js';
import {
  timelockEncrypt,
  timelockDecrypt
} from 'tlock-js';

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function main() {
  const message = "🔐 e-voting secret!";
  const delaySeconds = 10;

  const client = quicknet();

  const now = Math.floor(Date.now() / 1000);
  const unlockTime = now + delaySeconds;

  const chainInfo = await client.chain().info();
  const genesisTime = chainInfo.genesis_time;
  const period = chainInfo.period;

  console.log("Now:", now);
  console.log("UnlockTime:", unlockTime);
  console.log("Genesis Time:", genesisTime);

  if (unlockTime < genesisTime) {
    throw new Error("Unlock time is before genesis time.");
  }

  // Manual round calculation (avoids roundAt bug)
  const round = Math.floor((unlockTime - genesisTime) / period) + 1;
  console.log(`[+] Target round: ${round}`);

  const ciphertext = await timelockEncrypt(round, Buffer.from(message), client);
  console.log(`[+] Ciphertext:\n${ciphertext}`);

  try {
    console.log("[!] Trying early decryption...");
    const earlyPlain = await timelockDecrypt(ciphertext, client);
    console.log("[-] Unexpectedly decrypted early:", earlyPlain.toString());
  } catch (e) {
    console.log("[✓] Early decryption failed as expected:", e.message);
  }

while (true) {
  const roundInfo = await client.latest();
  const currentRound = roundInfo.round;

  if (currentRound >= round) break;
  console.log(`Waiting... Current round: ${currentRound}, Target: ${round}`);
  await sleep(1000);
}


  const decrypted = await timelockDecrypt(ciphertext, client);
  console.log(`[+] Decrypted message: "${decrypted.toString()}"`);
}

main().catch(console.error);
