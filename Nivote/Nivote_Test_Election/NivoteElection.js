import { HttpChainClient, timelockEncrypt, timelockDecrypt, roundForTime } from "tlock-js";

// Use Drand testnet URL
const TESTNET_URL = "https://pl-us.testnet.drand.sh";

async function main() {
    const client = new HttpChainClient(TESTNET_URL, { disableBeaconVerification: true });

    const message = "Hello from the future!";
    const delaySeconds = 60;

    const now = Math.floor(Date.now() / 1000);
    const targetTime = now + delaySeconds;

    const chainInfo = await client.chain().info();
    const round = roundForTime(targetTime, chainInfo);

    console.log("Encrypting for round:", round);

    const ciphertext = await timelockEncrypt(round, Buffer.from(message), client);
    console.log("Encrypted ciphertext:", ciphertext);

    // Wait until the round is available
    let currentRound = (await client.get()).round();
    while (currentRound < round) {
        console.log(`Waiting... current round: ${currentRound}, target: ${round}`);
        await new Promise(resolve => setTimeout(resolve, 5000));
        currentRound = (await client.get()).round();
    }

    const decrypted = await timelockDecrypt(ciphertext, client);
    console.log("Decrypted message:", decrypted.toString());
}

main().catch(console.error);
