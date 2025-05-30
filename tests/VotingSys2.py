from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from shamir_mnemonic import generate_mnemonics, combine_mnemonics
import random
import json

VOTERS = ["Tim","Tom","Ben","George"]

# Generation of secret key (16 bytes)
secretKey = get_random_bytes(16)
# For checking purposes
hexKey = secretKey.hex()
print("Secret Key: "+hexKey)

# Spliting the secretKey in equal parts for every Voter
nbrVoters = len(VOTERS)
group = [(nbrVoters,nbrVoters)]
mnemonics = generate_mnemonics(1, group, secretKey)

# Associate the voters to the share with a dictionary
voterShares={}

for i in range(nbrVoters):
    voter = VOTERS[i]
    share = mnemonics[0][i]
    voterShares[voter] = share

# Print the distributed shares
print("\nDistributed Shares:")
for voter, share in voterShares.items():
    print(f"\t{voter}: {share}")

encryptedVotes={}
for voter in VOTERS:
    # Randomize the vote
    if(random.randint(0,100)%2==0):
        vote = "Red"
    else:
        vote = "Blue"
    
    # AES-GCM Encryption (used for authenticated encryption)
    cipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, auth = cipher.encrypt_and_digest(vote.encode()) 

    encryptedVotes[voter] = {
    "iv": cipher.nonce.hex(),
    "ciphertext": ciphertext.hex(),
    "auth_tag": auth.hex()
    }

    print(voter+" has voted")

print("\nEncrypted Votes :")
print(json.dumps(encryptedVotes, indent=2))

collected_shares = []
for voter in VOTERS:
    collected_shares.append(voterShares[voter])

# Reconstruct Secret Key
reconstructed_key = combine_mnemonics(collected_shares)

# Validate key reconstruction
if reconstructed_key == secretKey:
    print("\nSuccessfully Reconstructed Secret Key")

    print("\nDecrypted Votes:")
    for voter, data in encryptedVotes.items():
        # Convert hex values back to bytes
        iv = bytes.fromhex(data["iv"])
        ciphertext = bytes.fromhex(data["ciphertext"])
        auth_tag = bytes.fromhex(data["auth_tag"])

        # Decrypt using AES-GCM
        cipher = AES.new(reconstructed_key, AES.MODE_GCM, nonce=iv)
        decrypted_vote = cipher.decrypt_and_verify(ciphertext, auth_tag)

        print(f"{voter} voted for: {decrypted_vote.decode()}") 
else:
    print("\nKey Reconstruction Failed!")
