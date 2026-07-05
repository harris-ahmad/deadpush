export type GpcMessage = {
  type: string;
  repo_id?: string;
  timestamp?: string;
  message_id?: string;
  payload?: Record<string, unknown>;
  protocol_version?: string;
};

export type GpcClient = { close: () => void };

export declare function gpcSocketPath(repoRoot: string, hardened?: boolean): string;
export declare function connectGpc(
  repoRoot: string,
  onMessage: (msg: GpcMessage) => void,
  options?: { hardened?: boolean; autoAck?: boolean },
): GpcClient;
