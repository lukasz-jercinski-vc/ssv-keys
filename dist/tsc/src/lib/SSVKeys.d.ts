import { IShares, ISharesKeyPairs } from './Threshold';
import { EncryptShare } from './Encryption/Encryption';
import { IOperator } from './KeyShares/KeySharesData/IOperator';
export interface ExtractedKeys {
    privateKey: string;
    publicKey: string;
}
/**
 * SSVKeys class provides high-level methods to easily work with entire flow:
 *  - getting private key from keystore file using password
 *  - creating shares threshold
 *  - creating final shares
 *  - building final payload which is ready to be used in web3 transaction
 */
export declare class SSVKeys {
    static SHARES_FORMAT_ABI: string;
    protected threshold: ISharesKeyPairs | undefined;
    /**
     * Extract private key from keystore data using keystore password.
     * Generally can be used in browsers when the keystore data has been provided by browser.
     * @param data
     * @param password
     */
    extractKeys(data: string, password: string): Promise<ExtractedKeys>;
    /**
     * Build threshold using private key for number of participants and failed participants.
     * @param privateKey
     * @param operators
     */
    createThreshold(privateKey: string, operators: IOperator[]): Promise<ISharesKeyPairs>;
    /**
     * Encrypt operators shares using operators public keys.
     * @param operatorsPublicKeys
     * @param shares
     * @param sharesFormat
     */
    encryptShares(operators: IOperator[], shares: IShares[]): Promise<EncryptShare[]>;
    /**
     * Build shares from private key, operator IDs and public keys
     * @param privateKey
     * @param operatorIds
     * @param operatorPublicKeys
     */
    buildShares(privateKey: string, operators: IOperator[]): Promise<EncryptShare[]>;
    /**
     * Getting threshold if it has been created before.
     */
    getThreshold(): ISharesKeyPairs | undefined;
}
