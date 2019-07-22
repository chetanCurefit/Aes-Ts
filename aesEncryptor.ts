const aesjs = require('aes-js');

export class AesEncryptor {
    private static addPadding(messageBytes: Uint8Array): Uint8Array {
        const byteLengthAfterPadding: number = messageBytes.length + (16 - (messageBytes.length % 16));
        const bytesAfterPadding: number[] = [];
        for (let i = 0; i < byteLengthAfterPadding; i++) {
            if (i < messageBytes.length) {
                bytesAfterPadding.push(messageBytes[i]);
            } else {
                bytesAfterPadding.push(0);
            }
        }
        return new Uint8Array(bytesAfterPadding);
    }

    public static encrypt(message: string, key: Uint8Array, iv: Uint8Array): string {
        if (key.length !== 128) {
            throw new Error('Invalid Key Size. Key size must be 128 bit.');
        } else if (iv.length !== 16) {
            throw new Error('Invalid Initialization Vector Size.');
        } else {
            const encyptor = new aesjs.ModeOfOperation.cbc(key, iv);
            const paddedMsg = this.addPadding(aesjs.utils.utf8.toBytes(message));
            const encryptedBytes = encyptor.encrypt(paddedMsg);
            return aesjs.utils.hex.fromBytes(encryptedBytes);
        }

    }
}


