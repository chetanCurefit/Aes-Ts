import * as crypto from 'crypto';


export class AesManaged {
    private ENCRYPTION_KEY: string = process.env.ENCRYPTION_KEY; // Must be 256 bits (32 characters)
    private IV_LENGTH = 16; // For AES, this is always 16

    constructor(key: string) {
        if (typeof key !== "string") {
            throw new Error('Encryption key must be a string');
        }
        if (key.length !== 32) {
            throw new Error('Encryption key must be 32 characters or 256 bit in length.');
        }
        this.ENCRYPTION_KEY = key;

    }

    public encrypt(text: string) {
        let iv: Buffer = crypto.randomBytes(this.IV_LENGTH);
        let cipher: crypto.Cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(this.ENCRYPTION_KEY), iv);
        let encrypted: Buffer = cipher.update(text);
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        return iv.toString('hex') + ':' + encrypted.toString('hex');
    }

    public decrypt(text: string) {
        let textParts: string[] = text.split(':');
        let iv: Buffer = Buffer.from(textParts.shift(), 'hex');
        let encryptedText: Buffer = Buffer.from(textParts.join(':'), 'hex');
        let decipher: crypto.Decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(this.ENCRYPTION_KEY), iv);
        let decrypted: Buffer = decipher.update(encryptedText);
        decrypted = Buffer.concat([decrypted, decipher.final()]);

        return decrypted.toString();
    }
}
