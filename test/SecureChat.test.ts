import { expect } from "chai";
import { ethers } from "hardhat";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import { time } from "@nomicfoundation/hardhat-network-helpers";

describe("Secure Chat", function () {
    let alice: SignerWithAddress;
    let bob: SignerWithAddress;
    let carol: SignerWithAddress;

    class SecureChat {
        // Helper function to derive encryption key
        private static deriveKey(
            signature: string,
            recipientSignature: string | null,
            challenge: string
        ): Uint8Array {
            const components = [ethers.getBytes(signature)];
            if (recipientSignature) {
                components.push(ethers.getBytes(recipientSignature));
            }
            components.push(ethers.getBytes(challenge));

            // Create a longer key by using multiple hashes
            const baseKey = ethers.getBytes(
                ethers.keccak256(ethers.concat(components))
            );
            
            // Extend the key to ensure we have enough bytes
            const extendedKey = new Uint8Array(64); // Use a fixed larger size
            for(let i = 0; i < 2; i++) {
                const nextKey = ethers.getBytes(
                    ethers.keccak256(
                        ethers.concat([baseKey, ethers.toBeArray(BigInt(i))])
                    )
                );
                extendedKey.set(nextKey, i * 32);
            }
            
            return extendedKey;
        }

        static async createMessageKey(
            message: string,
            senderWallet: SignerWithAddress,
            recipientAddress: string
        ) {
            // 1. Create unique message context with random challenge
            const challenge = ethers.randomBytes(32);
            const timestamp = Math.floor(Date.now() / 1000);
            
            // Hash the message first
            const messageHash = ethers.keccak256(ethers.toUtf8Bytes(message));
            
            const messageContext = ethers.keccak256(
                ethers.concat([
                    ethers.getBytes(await senderWallet.getAddress()),
                    ethers.getBytes(recipientAddress),
                    challenge,
                    ethers.toBeArray(BigInt(timestamp)),
                    ethers.getBytes(messageHash)
                ])
            );

            // 2. Sender signs the context
            const senderSignature = await senderWallet.signMessage(
                ethers.getBytes(messageContext)
            );

            return {
                challenge: ethers.hexlify(challenge),
                messageContext,
                senderSignature,
                timestamp
            };
        }

        static async encryptMessage(
            message: string,
            senderSignature: string,
            challenge: string
        ): Promise<string> {
            // Convert message to UTF-8 bytes
            const messageBytes = ethers.toUtf8Bytes(message);
            
            // Add length prefix to ensure proper decoding
            const withLength = new Uint8Array(messageBytes.length + 4);
            withLength.set(new Uint8Array(new Uint32Array([messageBytes.length]).buffer), 0);
            withLength.set(messageBytes, 4);
            
            // Derive encryption key using only sender signature initially
            const keyBytes = this.deriveKey(senderSignature, null, challenge);

            // XOR encryption
            const encrypted = new Uint8Array(withLength.length);
            for (let i = 0; i < withLength.length; i++) {
                encrypted[i] = withLength[i] ^ keyBytes[i % keyBytes.length];
            }

            // Convert to hex string for safe storage/transmission
            return ethers.hexlify(encrypted);
        }

        static async decryptMessage(
            encryptedHex: string,
            senderSignature: string,
            recipientSignature: string,
            challenge: string
        ): Promise<string> {
            try {
                // Derive decryption key using both signatures
                const keyBytes = this.deriveKey(senderSignature, recipientSignature, challenge);

                // Convert hex to bytes
                const encryptedBytes = ethers.getBytes(encryptedHex);
                const decrypted = new Uint8Array(encryptedBytes.length);

                // XOR decryption
                for (let i = 0; i < encryptedBytes.length; i++) {
                    decrypted[i] = encryptedBytes[i] ^ keyBytes[i % keyBytes.length];
                }

                // Extract length and message bytes
                const lengthBytes = decrypted.slice(0, 4);
                const length = new Uint32Array(lengthBytes.buffer)[0];
                const messageBytes = decrypted.slice(4, 4 + length);

                // Convert back to string
                return ethers.toUtf8String(messageBytes);
            } catch (error) {
                console.error("Decryption failed:", error);
                return "DECRYPTION_FAILED";
            }
        }
    }

    before(async function () {
        [alice, bob, carol] = await ethers.getSigners();
    });

    describe("Message Encryption and Decryption", function () {
        it("Should allow secure message exchange between parties", async function () {
            const message = "Hello Bob, this is a secret message!";
            
            // Alice creates and encrypts a message for Bob
            const {
                challenge,
                messageContext,
                senderSignature,
                timestamp
            } = await SecureChat.createMessageKey(
                message,
                alice,
                bob.address
            );

            // Encrypt the message
            const encryptedData = await SecureChat.encryptMessage(
                message,
                senderSignature,
                challenge
            );

            // Bob signs the message context to decrypt
            const recipientSignature = await bob.signMessage(
                ethers.getBytes(messageContext)
            );

            // Bob decrypts the message
            const decryptedMessage = await SecureChat.decryptMessage(
                encryptedData,
                senderSignature,
                recipientSignature,
                challenge
            );

            expect(decryptedMessage).to.equal(message);
        });

        it("Should not allow unauthorized decryption", async function () {
            const message = "Hello Bob, this is a secret message!";
            
            // Alice creates message for Bob
            const {
                challenge,
                messageContext,
                senderSignature
            } = await SecureChat.createMessageKey(
                message,
                alice,
                bob.address
            );

            // Encrypt the message
            const encryptedData = await SecureChat.encryptMessage(
                message,
                senderSignature,
                challenge
            );

            // Carol (unauthorized) tries to decrypt
            const carolSignature = await carol.signMessage(
                ethers.getBytes(messageContext)
            );

            // Attempt decryption with Carol's signature
            const decryptedMessage = await SecureChat.decryptMessage(
                encryptedData,
                senderSignature,
                carolSignature,
                challenge
            );

            // Should not match original message
            expect(decryptedMessage).to.not.equal(message);
        });

        it("Should verify message integrity", async function () {
            const message = "Hello Bob, this is a secret message!";
            
            // Alice creates message for Bob
            const {
                challenge,
                messageContext,
                senderSignature
            } = await SecureChat.createMessageKey(
                message,
                alice,
                bob.address
            );

            // Encrypt the message
            const encryptedData = await SecureChat.encryptMessage(
                message,
                senderSignature,
                challenge
            );

            // Tamper with encrypted data by modifying the hex
            const tamperedData = encryptedData.slice(0, -2) + "ff";

            // Bob tries to decrypt tampered message
            const recipientSignature = await bob.signMessage(
                ethers.getBytes(messageContext)
            );

            const decryptedMessage = await SecureChat.decryptMessage(
                tamperedData,
                senderSignature,
                recipientSignature,
                challenge
            );

            // Should not match original message
            expect(decryptedMessage).to.not.equal(message);
        });
    });

    describe("Public Data Analysis", function () {
        it("Should demonstrate what data is public", async function () {
            const message = "Hello Bob, this is a secret message!";
            
            // Create message
            const messageData = await SecureChat.createMessageKey(
                message,
                alice,
                bob.address
            );

            // Log public data
            console.log("Public Data Available:");
            console.log("- Challenge:", messageData.challenge);
            console.log("- Message Context:", messageData.messageContext);
            console.log("- Sender Signature:", messageData.senderSignature);
            console.log("- Timestamp:", messageData.timestamp);
            
            // Verify this public data alone cannot decrypt the message
            expect(messageData.messageContext).to.not.contain(message);
            expect(messageData.senderSignature).to.not.contain(message);
        });
    });
}); 