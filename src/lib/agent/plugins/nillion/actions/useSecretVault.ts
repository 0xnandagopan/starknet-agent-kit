import { checkCred, checkNode, SecretVaultWrapper } from "../utils/utils";
import type { Node } from "./../types/type";



export class SecretVault {
  private static instance: SecretVault | null = null;
  public wrapper: SecretVaultWrapper;

  constructor(nodeSpecifics: string) {
    this.wrapper = this.useSecretVault(nodeSpecifics);
  }

  private useSecretVault = (input: String): SecretVaultWrapper => {
    const nodes: Node[] = [];
    const nodeBlocks = input.split(/\n\n/);

    nodeBlocks.forEach((block) => {
      const urlMatch = block.match(/URL:\s*(https:\/\/[^\s]+)/);
      const didMatch = block.match(/DID:\s*(did:nil:testnet:nillion[a-z0-9]+)/);
      if (urlMatch && didMatch) {
        const url = urlMatch[1];
        const did = didMatch[1];

        const nilNode: Node = checkNode(url, did);

        nodes.push(nilNode);
      }
    });

    const cred = checkCred();

    const svWrapper = new SecretVaultWrapper(nodes, cred);
    return svWrapper;
  };

  public static initialize(nodeSpecifics: string): void {
    if (!SecretVault.instance) {
      SecretVault.instance = new SecretVault(nodeSpecifics);
    }
  }

  public static getInstance(): SecretVault {
    if (!SecretVault.instance) {
      throw new Error(
        "SecretVault is not initialized. Call initialize() first."
      );
    }
    return SecretVault.instance;
  }

  public static isInitialized(): boolean {
    return SecretVault.instance !== null;
  }
}
