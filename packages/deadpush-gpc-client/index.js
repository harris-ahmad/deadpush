/**
 * Minimal GPC client for Node.js 18+ (Unix socket, newline-delimited JSON).
 *
 * Usage:
 *   import { connectGpc } from "@deadpush/gpc-client";
 *   const c = connectGpc("/path/to/repo", (msg) => console.log(msg));
 */

import { createHash } from "node:crypto";
import { createConnection } from "node:net";
import { homedir } from "node:os";
import { join } from "node:path";

export type GpcMessage = {
  type: string;
  repo_id?: string;
  timestamp?: string;
  message_id?: string;
  payload?: Record<string, unknown>;
  protocol_version?: string;
};

function repoId(repoRoot: string): string {
  return createHash("sha256").update(repoRoot).digest("hex").slice(0, 12);
}

export function gpcSocketPath(repoRoot: string, hardened = false): string {
  const rid = repoId(repoRoot);
  if (hardened) {
    return join("/var/db/deadpush", `gpc.${rid}.sock`);
  }
  return join(homedir(), ".deadpush", `gpc.${rid}.sock`);
}

export type GpcClient = {
  close: () => void;
};

export function connectGpc(
  repoRoot: string,
  onMessage: (msg: GpcMessage) => void,
  options: { hardened?: boolean; autoAck?: boolean } = {},
): GpcClient {
  const socketPath = gpcSocketPath(repoRoot, options.hardened ?? false);
  const autoAck = options.autoAck ?? true;
  let buf = "";
  const conn = createConnection(socketPath);

  conn.on("data", (chunk) => {
    buf += chunk.toString("utf8");
    let idx: number;
    while ((idx = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, idx).trim();
      buf = buf.slice(idx + 1);
      if (!line) continue;
      try {
        const msg = JSON.parse(line) as GpcMessage;
        onMessage(msg);
        if (autoAck && msg.message_id && msg.type !== "ACK") {
          conn.write(
            JSON.stringify({ type: "ACK", message_id: msg.message_id, payload: { ack_for: msg.message_id } }) + "\n",
          );
        }
      } catch {
        /* ignore malformed */
      }
    }
  });

  return {
    close: () => {
      try {
        conn.end();
      } catch {
        /* ignore */
      }
    },
  };
}
