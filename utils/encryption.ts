import { ethers } from 'ethers';
import { Buffer } from 'buffer';
import { create } from 'ipfs-http-client';

// Encryption utility class
export class MessageEncryption {
    private static readonly ENCRYPTION_VERSION = 1;
    private static readonly ALGORITHM = 'aes-256-gcm';
    private static readonly IV_LENGTH = 16;
    private static readonly AUTH_TAG_LENGTH = 16;

    /**
     * Generate a random symmetric key for message encryption
     */
    static generateSymmetricKey(): Uint8Array {
        return crypto.getRandomValues(new Uint8Array(32));
    }

    /**
     * Generate a random nonce for message uniqueness
     */
    static generateNonce(): Uint8Array {
        return crypto.getRandomValues(new Uint8Array(16));
    }

    /**
     * Encrypt a message using a symmetric key
     */
    static async encryptMessage(
        message: string,
        symmetricKey: Uint8Array
    ): Promise<{
        encryptedMessage: Uint8Array;
        iv: Uint8Array;
        authTag: Uint8Array;
    }> {
        const iv = crypto.getRandomValues(new Uint8Array(this.IV_LENGTH));
        const encoder = new TextEncoder();
        const messageData = encoder.encode(message);

        const key = await crypto.subtle.importKey(
            'raw',
            symmetricKey,
            this.ALGORITHM,
            false,
            ['encrypt']
        );

        const encryptedData = await crypto.subtle.encrypt(
            {
                name: this.ALGORITHM,
                iv: iv,
            },
            key,
            messageData
        );

        // Extract auth tag from the end of encrypted data
        const encryptedArray = new Uint8Array(encryptedData);
        const encryptedMessage = encryptedArray.slice(0, -this.AUTH_TAG_LENGTH);
        const authTag = encryptedArray.slice(-this.AUTH_TAG_LENGTH);

        return {
            encryptedMessage,
            iv,
            authTag
        };
    }

    /**
     * Decrypt a message using a symmetric key
     */
    static async decryptMessage(
        encryptedMessage: Uint8Array,
        iv: Uint8Array,
        authTag: Uint8Array,
        symmetricKey: Uint8Array
    ): Promise<string> {
        const key = await crypto.subtle.importKey(
            'raw',
            symmetricKey,
            this.ALGORITHM,
            false,
            ['decrypt']
        );

        // Combine encrypted message and auth tag
        const encryptedData = new Uint8Array([
            ...encryptedMessage,
            ...authTag
        ]);

        const decryptedData = await crypto.subtle.decrypt(
            {
                name: this.ALGORITHM,
                iv: iv,
            },
            key,
            encryptedData
        );

        const decoder = new TextDecoder();
        return decoder.decode(decryptedData);
    }

    /**
     * Create a message hash for verification
     */
    static createMessageHash(
        encryptedMessage: Uint8Array,
        iv: Uint8Array,
        authTag: Uint8Array,
        nonce: Uint8Array
    ): string {
        const combinedData = new Uint8Array([
            ...encryptedMessage,
            ...iv,
            ...authTag,
            ...nonce
        ]);
        return ethers.keccak256(combinedData);
    }

    /**
     * Create an encryption proof signed by the recipient
     */
    static async createEncryptionProof(
        messageHash: string,
        recipientAddress: string,
        signer: ethers.Signer
    ): Promise<string> {
        const messageDataHash = ethers.keccak256(
            ethers.solidityPacked(
                ['address', 'bytes32', 'uint256'],
                [recipientAddress, messageHash, Math.floor(Date.now() / 1000)]
            )
        );
        return await signer.signMessage(ethers.getBytes(messageDataHash));
    }

    /**
     * Prepare message for IPFS storage
     */
    static prepareIPFSMessage(
        encryptedMessage: Uint8Array,
        iv: Uint8Array,
        authTag: Uint8Array,
        nonce: Uint8Array,
        version: number
    ): string {
        return JSON.stringify({
            encryptedMessage: Buffer.from(encryptedMessage).toString('base64'),
            iv: Buffer.from(iv).toString('base64'),
            authTag: Buffer.from(authTag).toString('base64'),
            nonce: Buffer.from(nonce).toString('base64'),
            version
        });
    }

    /**
     * Parse IPFS message
     */
    static parseIPFSMessage(ipfsData: string): {
        encryptedMessage: Uint8Array;
        iv: Uint8Array;
        authTag: Uint8Array;
        nonce: Uint8Array;
        version: number;
    } {
        const data = JSON.parse(ipfsData);
        return {
            encryptedMessage: Buffer.from(data.encryptedMessage, 'base64'),
            iv: Buffer.from(data.iv, 'base64'),
            authTag: Buffer.from(data.authTag, 'base64'),
            nonce: Buffer.from(data.nonce, 'base64'),
            version: data.version
        };
    }
}

// IPFS interaction class
export class IPFSService {
    private static ipfs = create({ url: process.env.IPFS_NODE_URL || 'https://ipfs.infura.io:5001' });

    /**
     * Upload encrypted message to IPFS
     */
    static async uploadEncryptedMessage(
        encryptedMessage: Uint8Array,
        iv: Uint8Array,
        authTag: Uint8Array,
        nonce: Uint8Array,
        version: number
    ): Promise<string> {
        const ipfsData = MessageEncryption.prepareIPFSMessage(
            encryptedMessage,
            iv,
            authTag,
            nonce,
            version
        );

        const result = await this.ipfs.add(ipfsData);
        return result.path;
    }

    /**
     * Fetch encrypted message from IPFS
     */
    static async fetchEncryptedMessage(ipfsHash: string): Promise<{
        encryptedMessage: Uint8Array;
        iv: Uint8Array;
        authTag: Uint8Array;
        nonce: Uint8Array;
        version: number;
    }> {
        const stream = this.ipfs.cat(ipfsHash);
        let data = '';
        
        for await (const chunk of stream) {
            data += chunk.toString();
        }

        return MessageEncryption.parseIPFSMessage(data);
    }
}

// Example usage:
/*
async function sendEncryptedMessage(
    message: string,
    recipientAddress: string,
    recipientPublicKey: string,
    signer: ethers.Signer
) {
    // 1. Generate symmetric key and nonce
    const symmetricKey = MessageEncryption.generateSymmetricKey();
    const nonce = MessageEncryption.generateNonce();

    // 2. Encrypt message
    const { encryptedMessage, iv, authTag } = await MessageEncryption.encryptMessage(
        message,
        symmetricKey
    );

    // 3. Create message hash
    const messageHash = MessageEncryption.createMessageHash(
        encryptedMessage,
        iv,
        authTag,
        nonce
    );

    // 4. Create encryption proof
    const encryptionProof = await MessageEncryption.createEncryptionProof(
        messageHash,
        recipientAddress,
        signer
    );

    // 5. Upload to IPFS
    const ipfsHash = await IPFSService.uploadEncryptedMessage(
        encryptedMessage,
        iv,
        authTag,
        nonce,
        MessageEncryption.ENCRYPTION_VERSION
    );

    // 6. Send to blockchain
    const contract = new ethers.Contract(
        CONTRACT_ADDRESS,
        CONTRACT_ABI,
        signer
    );

    await contract.sendEncryptedMessage(
        recipientAddress,
        messageHash,
        encryptionProof,
        ethers.keccak256(symmetricKey),
        ethers.keccak256(nonce),
        MessageEncryption.ENCRYPTION_VERSION,
        { value: FEE_AMOUNT }
    );

    return ipfsHash;
}
*/ 