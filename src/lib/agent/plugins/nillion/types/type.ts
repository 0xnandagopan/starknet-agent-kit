import { z } from "zod";
import { nilql } from '@nillion/nilql';

// <<- nilQl - wrapper.ts ->>

export const enum KeyType {
  CLUSTER = "cluster",
  SECRET = "secret",
}

// Zod schema for Cluster
export const ClusterSchema = z.object({
  nodes: z.array(z.object({})),
});

export type Cluster = z.infer<typeof ClusterSchema>;

// Zod schema for Operations
export const OperationsSchema = z
  .object({
    store: z.boolean().optional(),
    match: z.boolean().optional(),
    sum: z.boolean().optional(),
  })
  .refine(
    (data) => {
      const count = [data.store, data.match, data.sum].filter(Boolean).length;
      return count === 1;
    },
    { message: "Exactly one operation must be enabled" }
  );

export type Operations = z.infer<typeof OperationsSchema>;

// Get the *instance* types from the return type of the 'generate' methods.
export type SecretKeyType = Awaited<ReturnType<(typeof nilql.SecretKey)["generate"]>>;
export type ClusterKeyType = Awaited<
  ReturnType<(typeof nilql.ClusterKey)["generate"]>
>;

// Recursive type for encrypted data
export type EncryptedData<T> = T extends (infer U)[]
  ? EncryptedData<U>[] // Handle Arrays
  : T extends { $allot: any }
  ? { $allot: string | string[] | number[] } // Handle $allot
  : T extends object
  ? { [K in keyof T]: EncryptedData<T[K]> } // Handle nested objects
  : T;

// <<- SecretVault - wrapper.ts ->>

// --- Zod Schemas ---

export const NodeSchema = z.object({
  url: z.string().url(),
  did: z.string().regex(/^did:nil:testnet:nillion[a-z0-9]+$/),
});
export type Node = z.infer<typeof NodeSchema>;

export const CredentialsSchema = z.object({
  secretKey: z.string(),
  orgDid: z.string().regex(/^did:nil:testnet:nillion[a-z0-9]+$/),
});
export type Credentials = z.infer<typeof CredentialsSchema>;

export const NodeConfigSchema = z.object({
  url: z.string().url(),
  jwt: z.string(),
});
export type NodeConfig = z.infer<typeof NodeConfigSchema>;