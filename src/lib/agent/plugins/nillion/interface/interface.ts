// --- Error Response ---
// Use this for all 400 responses
export interface ErrorResponse400 {
  ts: string;
  errors: (string | { code: string; message: string })[];
}

// --- /data/flush specific types ---
export interface FlushDataRequest {
  schema: string;
}

export interface FlushDataResponse200 {
  data: number;
}

export type FlushDataResult =
  | { node: string; result: FlushDataResponse200 }
  | { node: string; error: ErrorResponse400 | string };


// GET /schemas
export interface GetSchemasResponse200 {
  data: SchemaObject[];
}

export interface SchemaObject {
  _id: string;
  _created: string;
  _updated: string;
  name: string;
  owner: string;
  keys: string[];
  schema: object; // Could be more specific
}

export type GetSchemasResult =
  | { node: string; result: GetSchemasResponse200 }
  | { node: string; error: ErrorResponse400 | string };

// POST /schemas
export interface CreateSchemaRequest {
  // Renamed from PostSchemasRequest
  _id: string;
  name: string;
  keys: string[];
  schema: object; // Could be more specific
}

//Assuming for now, it returns created schema object, it may return an object with just _id
export interface CreateSchemaResponse200 {
  // Renamed from PostSchemasResponse200
  data: string; // According to the CSV, it is returning just an ID.
}

export type CreateSchemaResult =
  | { node: string; result: CreateSchemaResponse200 }
  | { node: string; error: ErrorResponse400 | string };

// DELETE /schemas
export interface DeleteSchemasRequest {
  id: string;
}

export interface DeleteSchemasResponse200 {
  data: string; //According to the CSV
}

export type DeleteSchemasResult =
  | { node: string; result: DeleteSchemasResponse200 }
  | { node: string; error: ErrorResponse400 | string };


// --- /data/create specific types ---
export interface WriteToNodesRequest {
  schema: string;
  data: object[];
}

export interface WriteToNodesResponse200 {
  created: (null | string)[]; // Array of IDs or null
  errors: { error: string; document: object }[];
}

export type WriteToNodesResult =
  | { node: string; result: WriteToNodesResponse200 }
  | { node: string; error: ErrorResponse400 | string };


// --- /data/read specific types ---
export interface ReadFromNodesRequest {
  schema: string;
  filter: object;
}

export interface ReadFromNodesResponse200 {
  data: RecordObject[];
}

export interface RecordObject {
  [key: string]: any; // Index signature: allows any string key
  _id: string; // But _id MUST be present
}


// ---/data/update specific types ---
export interface UpdateDataToNodesRequest {
  schema: string;
  filter: object;
  update: object;
}

export interface UpdateDataToNodesResponse200 {
  data: {
    matched: number;
    updated: number;
  };
}

export type UpdateDataToNodesResult =
  | { node: string; result: UpdateDataToNodesResponse200 }
  | { node: string; error: ErrorResponse400 | string };


// --- /data/delete specific types ---
export interface DeleteDataFromNodesRequest {
  schema: string;
  filter: object;
}

export interface DeleteDataFromNodesResponse200 {
  data: number;
}

export type DeleteDataFromNodesResult =
  | { node: string; result: DeleteDataFromNodesResponse200 }
  | { node: string; error: ErrorResponse400 | string };


// --- /data/tail specific types ---
export interface TailDataRequest {
  schema: string;
}
export interface TailDataResponse200 {
  data: object[];
}
