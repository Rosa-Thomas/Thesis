// tlock.js
import * as drand from "drand-client";
import * as age from "@zkochan/age";

export class TLock {
  constructor(network = "quicknet") {
    this.client = drand.createClient({ network });
    this.genesisTime = null;
    this.period = null;
  }

  async _init() {
    if (!this.genesisTime || !this.period) {
      this.genesisTime = await this.client.getGenesisTime();
      this.period = await this.client.getPeriod();
    }
  }

  async _nowInSeconds() {
    return Math.floor(Date.now() / 1000);
  }

  async secondsToRound(seconds) {
    await this._init();
    const now = await this._nowInSeconds();
    const targetTime = now + seconds;

    if (targetTime < this.genesisTime) {
      throw new Error("Target time before genesis time");
    }

    return Math.ceil((targetTime - this.genesisTime) / this.period);
  }

  async encrypt(message, delaySeconds = 10) {
    const round = await this.secondsToRound(delaySeconds);
    const encrypted = await age.encrypt(message, round);
    return { encrypted, unlockRound: round };
  }

  async decrypt(encryptedObj) {
    await this._init();
    const now = await this._nowInSeconds();
    const currentRound = Math.floor((now - this.genesisTime) / this.period);

    if (currentRound < encryptedObj.unlockRound) {
      throw new Error(`Too early to decrypt: current round ${currentRound}, unlock round ${encryptedObj.unlockRound}`);
    }

    return await age.decrypt(encryptedObj.encrypted);
  }
}
