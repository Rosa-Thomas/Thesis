import { quicknet } from './client-utils.js';
import { timelockEncrypt, timelockDecrypt } from 'tlock-js';

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

export async function timeLockMessage(message, delaySeconds) {
  const client = quicknet();

  const now = Math.floor(Date.now() / 1000);
  const unlockTime = now + delaySeconds;

  const chainInfo = await client.chain().info();
  const genesisTime = chainInfo.genesis_time;
  const period = chainInfo.period;

  if (unlockTime < genesisTime) {
    throw new Error("Unlock time is before genesis time.");
  }

  const round = Math.floor((unlockTime - genesisTime) / period) + 1;

  const ciphertext = await timelockEncrypt(round, Buffer.from(message), client);

  // Wait until drand round reaches unlock round
  while (true) {
    const roundInfo = await client.latest();
    if (roundInfo.round >= round) break;
    await sleep(1000);
  }

  const decrypted = await timelockDecrypt(ciphertext, client);
  return decrypted.toString();
}
