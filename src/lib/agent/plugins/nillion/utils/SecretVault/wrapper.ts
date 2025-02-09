import { createJWT, ES256KSigner } from "did-jwt";
import { Buffer } from "buffer";
import { NilQLWrapper } from "../nilQl/wrapper";
import { v4 as uuidv4 } from "uuid";
import { z } from "zod";

import { NodeSchema, CredentialsSchema, NodeConfigSchema } from '../../types/type';
import type { Node, Credentials, NodeConfig } from '../../types/type';
import type { ErrorResponse400, FlushDataRequest, FlushDataResponse200, GetSchemasResponse200, SchemaObject, CreateSchemaRequest, CreateSchemaResponse200, DeleteSchemasRequest, DeleteSchemasResponse200, WriteToNodesRequest, WriteToNodesResponse200, ReadFromNodesRequest, ReadFromNodesResponse200, RecordObject, UpdateDataToNodesRequest, UpdateDataToNodesResponse200, DeleteDataFromNodesRequest, DeleteDataFromNodesResponse200, TailDataRequest, TailDataResponse200 } from '../../interface/interface';
import type { FlushDataResult, GetSchemasResult, CreateSchemaResult, DeleteSchemasResult, WriteToNodesResult, UpdateDataToNodesResult, DeleteDataFromNodesResult } from '../../interface/interface';



/**
 * SecretVaultWrapper manages distributed data storage across multiple nodes.
 * It handles node authentication, data distribution, and uses NilQLWrapper
 * for field-level encryption. Provides CRUD operations with built-in
 * security and error handling.
 *
 * @example
 * const vault = new SecretVaultWrapper(nodes, credentials, schemaId);
 * await vault.init();
 * await vault.writeToNodes(data, ['sensitiveField']);
 */
export class SecretVaultWrapper {
  private nodes: Node[];
  private nodesJwt: NodeConfig[] | null;
  private credentials: Credentials;
  private schemaId: string | null;
  private operation: "store" | "match" | "sum";
  private tokenExpirySeconds: number;
  private nilqlWrapper: NilQLWrapper | null;

  constructor(
    nodes: Node[],
    credentials: Credentials,
    schemaId: string | null = null,
    operation: "store" | "match" | "sum" = "store",
    tokenExpirySeconds: number = 3600
  ) {
    // Validate inputs
    z.array(NodeSchema).parse(nodes);
    CredentialsSchema.parse(credentials);
    if (schemaId) {
      z.string().parse(schemaId);
    }
    z.enum(["store", "match", "sum"]).parse(operation);
    z.number().int().positive().parse(tokenExpirySeconds);

    this.nodes = nodes;
    this.nodesJwt = null;
    this.credentials = credentials;
    this.schemaId = schemaId;
    this.operation = operation;
    this.tokenExpirySeconds = tokenExpirySeconds;
    this.nilqlWrapper = null;
  }

  /**
   * Initializes the SecretVaultWrapper by generating tokens for all nodes
   * and setting up the NilQLWrapper
   * @returns {Promise<NilQLWrapper>} Initialized NilQLWrapper instance
   */
  async init(): Promise<NilQLWrapper> {
    const nodeConfigs = await Promise.all(
      this.nodes.map(async (node) => ({
        url: node.url,
        jwt: await this.generateNodeToken(node.did),
      }))
    );
    this.nodesJwt = nodeConfigs;
    this.nilqlWrapper = new NilQLWrapper({ nodes: this.nodes }, this.operation);
    await this.nilqlWrapper.init();
    return this.nilqlWrapper;
  }

  /**
   * Updates the schema ID for the SecretVaultWrapper
   * @param {string} schemaId - The new schema ID
   */
  setSchemaId(
    schemaId: string,
    operation: "store" | "match" | "sum" = this.operation
  ): void {
    z.string().parse(schemaId);
    z.enum(["store", "match", "sum"]).parse(operation);
    this.schemaId = schemaId;
    this.operation = operation;
  }

  /**
   * Generates a JWT token for node authentication
   * @param {string} nodeDid - The DID of the node to generate token for
   * @returns {Promise<string>} JWT token
   */
  async generateNodeToken(nodeDid: string): Promise<string> {
    z.string().parse(nodeDid); // Validate DID
    const signer = ES256KSigner(Buffer.from(this.credentials.secretKey, "hex"));
    const payload = {
      iss: this.credentials.orgDid,
      aud: nodeDid,
      exp: Math.floor(Date.now() / 1000) + this.tokenExpirySeconds,
    };
    return await createJWT(payload, {
      issuer: this.credentials.orgDid,
      signer,
    });
  }

  /**
   * Generates tokens for all nodes and returns an array of objects containing node and token
   * @returns {Promise<Array<{ node: string, token: string }>>} Array of nodes with their corresponding tokens
   */
  async generateTokensForAllNodes(): Promise<
    Array<{ node: string; token: string }>
  > {
    const tokens = await Promise.all(
      this.nodes.map(async (node) => {
        const token = await this.generateNodeToken(node.did);
        return { node: node.url, token };
      })
    );
    return tokens;
  }

  /**
   * Makes an HTTP request to a node's endpoint.
   * @param {string} nodeUrl - URL of the node.
   * @param {string} endpoint - API endpoint.
   * @param {string} token - JWT token for authentication.
   * @param {object} payload - Request payload.
   * @param {'POST' | 'GET' | 'DELETE'} [method='POST'] - HTTP method.
   * @returns {Promise<T>} Response data.
   * @throws {Error} If the HTTP request fails.
   */
  async makeRequest<T>(
    nodeUrl: string,
    endpoint: string,
    token: string,
    payload: object,
    method: "POST" | "GET" | "DELETE" = "POST"
  ): Promise<T> {
    z.string().url().parse(nodeUrl);
    z.string().parse(endpoint);
    z.string().parse(token);
    z.object({}).parse(payload);

    const response = await fetch(`${nodeUrl}/api/v1/${endpoint}`, {
      method,
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: method === "GET" ? null : JSON.stringify(payload),
    });

    if (!response.ok) {
      const text = await response.text();
      // Instead of throwing error, return the response
      return (await response.json()) as T; //type assertion
    }

    return await response.json();
  }

  /**
   * Transforms data by encrypting specified fields across all nodes
   * @param {object[]} data - Data to transform
   * @returns {Promise<object[][]>} Array of transformed data for each node
   */
  async allotData(data: object[]): Promise<object[][]> {
    // Check if nilqlWrapper is initialized
    if (!this.nilqlWrapper) {
      throw new Error("NilQLWrapper not initialized. Call init() first.");
    }
    const encryptedRecords = [];
    for (const item of data) {
      const encryptedItem = await this.nilqlWrapper.prepareAndAllot(item);
      encryptedRecords.push(encryptedItem);
    }
    return encryptedRecords;
  }

  /**
   * Flushes (clears) data from all nodes for the current schema
   * @returns {Promise<FlushDataResult[]>} Array of flush results from each node
   */
  async flushData(): Promise<FlushDataResult[]> {
    if (!this.schemaId) {
      throw new Error(
        "Schema ID is not set. Please set a schema ID using setSchemaId()."
      );
    }

    const results: FlushDataResult[] = [];
    for (const node of this.nodes) {
      const jwt = await this.generateNodeToken(node.did);
      const payload: FlushDataRequest = { schema: this.schemaId }; // Use the interface
      try {
        const result = await this.makeRequest<FlushDataResponse200>(
          node.url,
          "data/flush",
          jwt,
          payload
        );
        results.push({ node: node.url, result });
      } catch (error: any) {
        if (error.errors && Array.isArray(error.errors)) {
          results.push({ node: node.url, error: error as ErrorResponse400 });
        } else {
          results.push({ node: node.url, error: error.message });
        }
      }
    }
    return results;
  }

  /**
   * Lists schemas from all nodes in the org
   * @returns {Promise<SchemaObject[]>} Array of schema objects
   */
  async getSchemas(): Promise<SchemaObject[]> {
    const results: GetSchemasResult[] = [];
    for (const node of this.nodes) {
      const jwt = await this.generateNodeToken(node.did);
      try {
        const result = await this.makeRequest<GetSchemasResponse200>(
          node.url,
          "schemas",
          jwt,
          {},
          "GET"
        );
        results.push({ node: node.url, result });
      } catch (error: any) {
        if (error.errors && Array.isArray(error.errors)) {
          results.push({ node: node.url, error: error as ErrorResponse400 });
        } else {
          results.push({ node: node.url, error: error.message });
        }
      }
    }
    return results.flatMap((res) => ("result" in res ? res.result.data : []));
  }

  /**
   * Creates a new schema on all nodes.
   * @param {object} schema - The schema definition.
   * @param {string} schemaName - The name of the schema.
   * @param {string} [schemaId] - Optional schema ID.  If not provided, one will be generated.
   * @returns {Promise<CreateSchemaResult[]>} An array of results, one for each node.
   */
  async createSchema(
    schema: object,
    schemaName: string,
    schemaId?: string
  ): Promise<CreateSchemaResult[]> {
    z.object({}).parse(schema);
    z.string().parse(schemaName);

    if (!schemaId) {
      schemaId = uuidv4();
    } else {
      z.string().parse(schemaId);
    }

    const schemaPayload: CreateSchemaRequest = {
      _id: schemaId,
      name: schemaName,
      keys: ["_id"], // Assuming _id is always a key
      schema,
    };

    const results: CreateSchemaResult[] = [];
    for (const node of this.nodes) {
      const jwt = await this.generateNodeToken(node.did);
      try {
        const result = await this.makeRequest<CreateSchemaResponse200>(
          node.url,
          "schemas",
          jwt,
          schemaPayload,
          "POST"
        );
        results.push({ node: node.url, result });
      } catch (error: any) {
        if (error.errors && Array.isArray(error.errors)) {
          results.push({ node: node.url, error: error as ErrorResponse400 });
        } else {
          results.push({ node: node.url, error: error.message });
        }
      }
    }
    return results;
  }

  /**
   * Deletes a schema from all nodes.
   * @param {string} schemaId The ID of the schema to delete.
   * @returns {Promise<DeleteSchemasResult[]>} An array of results, one for each node.
   */
  async deleteSchema(schemaId: string): Promise<DeleteSchemasResult[]> {
    z.string().parse(schemaId);

    const results: DeleteSchemasResult[] = [];
    for (const node of this.nodes) {
      const jwt = await this.generateNodeToken(node.did);
      const payload: DeleteSchemasRequest = { id: schemaId };
      try {
        const result = await this.makeRequest<DeleteSchemasResponse200>(
          node.url,
          "schemas",
          jwt,
          payload,
          "DELETE"
        );
        results.push({ node: node.url, result });
      } catch (error: any) {
        if (error.errors && Array.isArray(error.errors)) {
          results.push({ node: node.url, error: error as ErrorResponse400 });
        } else {
          results.push({ node: node.url, error: error.message });
        }
      }
    }
    return results;
  }

  /**
   * Writes data to all nodes, with optional field encryption
   * @param {object[]} data - Data to write
   * @returns {Promise<WriteToNodesResult[]>} Array of write results from each node
   */
  async writeToNodes(data: object[]): Promise<WriteToNodesResult[]> {
    if (!this.schemaId) {
      throw new Error(
        "Schema ID is not set. Please set a schema ID using setSchemaId()."
      );
    }
    // add a _id field to each record if it doesn't exist
    const idData = data.map((record) => {
      if (!record.hasOwnProperty("_id")) {
        return { ...record, _id: uuidv4() };
      }
      return record;
    });

    const transformedData = await this.allotData(idData);

    const results: WriteToNodesResult[] = [];

    for (let i = 0; i < this.nodes.length; i++) {
      const node = this.nodes[i];
      try {
        const nodeData = transformedData.map((encryptedShares) => {
          // if the data was not meant to be split across multiple nodes
          if (encryptedShares.length !== this.nodes.length) {
            return encryptedShares[0];
          }
          return encryptedShares[i];
        });
        const jwt = await this.generateNodeToken(node.did);
        const payload: WriteToNodesRequest = {
          schema: this.schemaId,
          data: nodeData,
        };
        const result = await this.makeRequest<WriteToNodesResponse200>(
          node.url,
          "data/create",
          jwt,
          payload
        );
        results.push({ node: node.url, result });
      } catch (error: any) {
        if (error.errors && Array.isArray(error.errors)) {
          results.push({ node: node.url, error: error as ErrorResponse400 });
        } else {
          results.push({ node: node.url, error: error.message });
        }
      }
    }

    return results;
  }

  /**
   * Reads data from all nodes with optional decryption of specified fields
   * @param {object} [filter={}] - Filter criteria for reading data
   * @returns {Promise<object[]>} Array of decrypted records
   */
  async readFromNodes(filter: object = {}): Promise<object[]> {
    if (!this.schemaId) {
      throw new Error(
        "Schema ID is not set. Please set a schema ID using setSchemaId()."
      );
    }
    // Check if nilqlWrapper is initialized
    if (!this.nilqlWrapper) {
      throw new Error("NilQLWrapper not initialized. Call init() first.");
    }
    const resultsFromAllNodes: { node: string; data: RecordObject[] }[] = [];

    for (const node of this.nodes) {
      try {
        const jwt = await this.generateNodeToken(node.did);
        const payload: ReadFromNodesRequest = { schema: this.schemaId, filter };
        const result = await this.makeRequest<ReadFromNodesResponse200>(
          node.url,
          "data/read",
          jwt,
          payload
        );
        resultsFromAllNodes.push({ node: node.url, data: result.data });
      } catch (error: any) {
        console.error(`❌ Failed to read from ${node.url}:`, error.message);
        resultsFromAllNodes.push({ node: node.url, data: [] }); // Push empty array on error
      }
    }

    // Group records across nodes by _id
    const recordGroups: { shares: RecordObject[]; recordIndex: string }[] =
      resultsFromAllNodes.reduce(
        (
          acc: { shares: RecordObject[]; recordIndex: string }[],
          nodeResult
        ) => {
          nodeResult.data.forEach((record: RecordObject) => {
            const existingGroup = acc.find((group) =>
              group.shares.some(
                (share: RecordObject) => share._id === record._id
              )
            );
            if (existingGroup) {
              existingGroup.shares.push(record);
            } else {
              acc.push({ shares: [record], recordIndex: record._id });
            }
          });
          return acc;
        },
        []
      );

    const recombinedRecords = await Promise.all(
      recordGroups.map(async (record) => {
        if (!this.nilqlWrapper) {
          throw new Error("NilQl wrapper not initialized, call init() first.");
        }
        const recombined = await this.nilqlWrapper.unify(record.shares);
        return recombined;
      })
    );
    return recombinedRecords;
  }

  /**
   * Updates data on all nodes, with optional field encryption
   * @param {object} recordUpdate - Data to update
   * @param {object} [filter={}] - Filter criteria for which records to update
   * @returns {Promise<UpdateDataToNodesResult[]>} Array of update results from each node
   */
  async updateDataToNodes(
    recordUpdate: object,
    filter: object = {}
  ): Promise<UpdateDataToNodesResult[]> {
    if (!this.schemaId) {
      throw new Error(
        "Schema ID is not set. Please set a schema ID using setSchemaId()."
      );
    }

    const results: UpdateDataToNodesResult[] = [];

    const transformedData = await this.allotData([recordUpdate]);
    for (let i = 0; i < this.nodes.length; i++) {
      const node = this.nodes[i];
      try {
        const [nodeData] = transformedData.map((encryptedShares) => {
          if (encryptedShares.length !== this.nodes.length) {
            return encryptedShares[0];
          }
          return encryptedShares[i];
        });
        const jwt = await this.generateNodeToken(node.did);
        const payload: UpdateDataToNodesRequest = {
          schema: this.schemaId,
          update: {
            $set: nodeData,
          },
          filter,
        };
        const result = await this.makeRequest<UpdateDataToNodesResponse200>(
          node.url,
          "data/update",
          jwt,
          payload
        );
        results.push({ node: node.url, result });
      } catch (error: any) {
        if (error.errors && Array.isArray(error.errors)) {
          results.push({ node: node.url, error: error as ErrorResponse400 });
        } else {
          results.push({ node: node.url, error: error.message });
        }
      }
    }
    return results;
  }

  /**
   * Deletes data from all nodes based on the provided filter
   * @param {object} [filter={}] - Filter criteria for which records to delete
   * @returns {Promise<DeleteDataFromNodesResult[]>} Array of deletion results from each node
   */
  async deleteDataFromNodes(
    filter: object = {}
  ): Promise<DeleteDataFromNodesResult[]> {
    if (!this.schemaId) {
      throw new Error(
        "Schema ID is not set. Please set a schema ID using setSchemaId()."
      );
    }
    const results: DeleteDataFromNodesResult[] = [];

    for (const node of this.nodes) {
      try {
        const jwt = await this.generateNodeToken(node.did);
        const payload: DeleteDataFromNodesRequest = {
          schema: this.schemaId,
          filter,
        };
        const result = await this.makeRequest<DeleteDataFromNodesResponse200>(
          node.url,
          "data/delete",
          jwt,
          payload
        );
        results.push({ node: node.url, result });
      } catch (error: any) {
        if (error.errors && Array.isArray(error.errors)) {
          results.push({ node: node.url, error: error as ErrorResponse400 });
        } else {
          results.push({ node: node.url, error: error.message });
        }
      }
    }
    return results;
  }
}
