import { nilql } from '@nillion/nilql';
import { KeyType, ClusterSchema, OperationsSchema } from '../../types/type';
import type {  Cluster,  Operations, SecretKeyType, ClusterKeyType, EncryptedData } from '../../types/type';

/**
 * NilQLWrapper provides encryption and decryption of data using Nillion's technology.
 * It generates and manages secret keys, splits data into shares when encrypting,
 * and recombines shares when decrypting.
 *
 * @example
 * const wrapper = new NilQLWrapper(cluster);
 * await wrapper.init();
 * const shares = await wrapper.encrypt(sensitiveData);
 */
export class NilQLWrapper {
  private cluster: Cluster;
  private secretKey:  SecretKeyType | ClusterKeyType | null;
  private operation: Operations;
  private keyType: KeyType;

  constructor(
    cluster: Cluster,
    operation: "store" | "match" | "sum" = "store",
    secretKey:  SecretKeyType | ClusterKeyType | null = null, // option to pass in your own secret key
    keyType: KeyType = KeyType.CLUSTER
  ) {
    ClusterSchema.parse(cluster); // Validate cluster
    this.cluster = cluster;

    this.secretKey = secretKey;

    const operationObj: Operations = {};
    operationObj[operation] = true;
    OperationsSchema.parse(operationObj);
    this.operation = operationObj;

    this.keyType = keyType;
  }

  /**
   * Initializes the NilQLWrapper by generating and storing a secret key
   * for the cluster. This must be called before any encryption/decryption operations.
   * @returns {Promise<void>}
   */
  async init(): Promise<void> {
    if (this.secretKey === null && this.keyType === KeyType.SECRET) {
      this.secretKey = await nilql.SecretKey.generate(
        this.cluster,
        this.operation
      );
    }
    if (this.keyType === KeyType.CLUSTER) {
      this.secretKey = await nilql.ClusterKey.generate(
        this.cluster,
        this.operation
      );
    }
  }

  /**
   * Encrypts data using the initialized secret key
   * @param {any} data - The data to encrypt
   * @throws {Error} If NilQLWrapper hasn't been initialized
   * @returns {Promise<string | string[] | number[]>} Array of encrypted shares
   */
  async encrypt(data: number | bigint | string): Promise<string | string[] | number[]> {
    if (!this.secretKey) {
      throw new Error('NilQLWrapper not initialized. Call init() first.');
    }
    const shares = await nilql.encrypt(this.secretKey, data);
    return shares;
  }

  /**
   * Decrypts data using the initialized secret key and provided shares
   * @param {Array<string | number>} shares - Array of encrypted shares to decrypt.  Can be strings or numbers.
   * @throws {Error} If NilQLWrapper hasn't been initialized
   * @returns {Promise<bigint | string>} The decrypted data
   */
  async decrypt(shares: string | string[] | number[]): Promise<bigint | string> {
    if (!this.secretKey) {
      throw new Error('NilQLWrapper not initialized. Call init() first.');
    }
    const decryptedData = await nilql.decrypt(this.secretKey, shares);
    return decryptedData;
  }

   /**
   * Recursively encrypts all values marked with $allot in the given data object
   * and prepares it for secure processing.
   *
   * - Traverses the entire object structure, handling nested objects at any depth.
   * - Encrypts values associated with the $allot key using nilql.encrypt().
   * - Preserves non-$allot values and maintains the original object structure.
   * - Calls nilql.allot() on the fully processed data before returning.
   *
   * @param {object} data - The input object containing fields marked with $allot for encryption.
   * @throws {Error} If NilQLWrapper has not been initialized with a secret key.
   * @returns {Promise<object[]>} The processed object with encrypted $allot values.
   */
   async prepareAndAllot(data: object): Promise<object[]> {
    if (!this.secretKey) {
      throw new Error('NilQLWrapper not initialized. Call init() first.');
    }

    const encryptDeep = async <T extends object>(obj: T): Promise<EncryptedData<T>> => {
      if (typeof obj !== 'object' || obj === null) {
        return obj as EncryptedData<T>;
      }

      if (!this.secretKey) {
        throw new Error('NilQLWrapper not initialized. Call init() first.');
      }

      const encrypted: any = Array.isArray(obj) ? [] : {};

      for (const [key, value] of Object.entries(obj)) {
        if (typeof value === 'object' && value !== null) {
          if ('$allot' in value) {
            // Type assertion is still needed, but it's more targeted now.
            encrypted[key] = {
              $allot: await nilql.encrypt(this.secretKey, (value as { $allot: any }).$allot),
            };
          } else {
            encrypted[key] = await encryptDeep(value); // Recurse into nested objects
          }
        } else {
          encrypted[key] = value;
        }
      }
      return encrypted;
    };

    const encryptedData = await encryptDeep(data);
    return nilql.allot(encryptedData);
  }

  /**
   * Recombines encrypted shares back into original data structure
   * @param {object[]} shares - Array of shares from prepareAndAllot
   * @throws {Error} If NilQLWrapper hasn't been initialized
   * @returns {Promise<object | Array<object>>} Original data structure with decrypted values
   */
  async unify(shares: object[]): Promise<object | Array<object>> {
    if (!this.secretKey) {
        throw new Error('NilQLWrapper not initialized. Call init() first.');
    }
    const unifiedResult = await nilql.unify(this.secretKey, shares);
    return unifiedResult;
  }
}
