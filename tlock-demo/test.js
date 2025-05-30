class TLock {
  constructor() {
    this.roundDuration = 30; // global delay in seconds
  }

  async encrypt(message, delaySeconds) {
    const delay = delaySeconds ?? this.roundDuration;
    console.log(`Encrypting message with ${delay} seconds delay...`);

    // simulate encryption delay
    await new Promise(resolve => setTimeout(resolve, delay * 1000));

    // dummy encryption output (base64 encode message)
    const encrypted = Buffer.from(message).toString('base64');

    console.log("Encrypted:", encrypted);
    return encrypted;
  }

  async decrypt(encrypted) {
    console.log("Trying to decrypt...");

    // simulate some processing delay (e.g. 2 seconds)
    await new Promise(resolve => setTimeout(resolve, 2000));

    // dummy decrypt (base64 decode)
    const decrypted = Buffer.from(encrypted, 'base64').toString();

    console.log("Decrypted:", decrypted);
    return decrypted;
  }
}

async function runTest() {
  const tlock = new TLock();

  // change delay globally
  tlock.roundDuration = 15;

  // encrypt with default delay (10s)
  const encrypted = await tlock.encrypt("Hello World!");

  try {
    // try decrypt immediately after encryption
    const decrypted = await tlock.decrypt(encrypted);
  } catch (err) {
    console.error("Decrypt error:", err.message);
  }
}

runTest();
