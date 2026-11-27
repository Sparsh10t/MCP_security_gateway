/**
 * Bridges the MCP SDK's Web Fetch API handler onto an Express route.
 *
 * Problem: MCP SDK uses modern Web standard (Request/Response/ReadableStream).
 *          Express uses Node.js's older HTTP API (req/res streams).
 *          They're incompatible, so we need this adapter.
 *
 * Must be mounted BEFORE express.json() — the SDK reads the raw body itself.
 */

import { Readable } from "node:stream";
import type { ReadableStream as NodeWebReadableStream } from "node:stream/web";
import type { Response as ExpressResponse, RequestHandler } from "express";
import type { McpHttpHandler } from "@modelcontextprotocol/server";
import type { AuthenticatedRequest } from "../middleware/authMiddleware.js";

export function expressMcpHandler(handler: McpHttpHandler): RequestHandler {
  return async (req: AuthenticatedRequest, res: ExpressResponse, next) => {
    try {
      // Reconstruct the full URL from Express's split-up request info
      const protocol = req.protocol || "http";
      const host = req.get("host") || "localhost";
      const url = new URL(req.originalUrl, `${protocol}://${host}`);

      // Convert Express headers object → Web Headers instance
      const headers = new Headers();
      for (const [key, value] of Object.entries(req.headers)) {
        if (value === undefined) continue;
        if (Array.isArray(value)) {
          for (const item of value) headers.append(key, item);
        } else {
          headers.set(key, value);
        }
      }

      // Build the Web Request (GET/HEAD have no body)
      const hasBody = req.method !== "GET" && req.method !== "HEAD";
      const init: RequestInit & { duplex?: "half" } = { method: req.method, headers };
      if (hasBody) {
        init.body = Readable.toWeb(req) as unknown as NonNullable<RequestInit["body"]>;
        init.duplex = "half"; // required when streaming body in Node 18+
      }

      // Pass the Web Request to the MCP SDK handler
      const webRequest = new globalThis.Request(url, init);
      const webResponse = await handler.fetch(webRequest, {
        ...(req.authInfo !== undefined ? { authInfo: req.authInfo } : {}),
      });

      // Copy status + headers back to Express response
      res.status(webResponse.status);
      webResponse.headers.forEach((value, key) => res.setHeader(key, value));

      if (!webResponse.body) {
        res.end();
        return;
      }

      // Stream the response body (MCP uses SSE — a long-lived streaming response)
      res.flushHeaders();
      const nodeStream = Readable.fromWeb(
        webResponse.body as unknown as NodeWebReadableStream<Uint8Array>
      );

      // Clean up the stream if the client disconnects
      req.on("close", () => {
        if (!res.writableEnded) nodeStream.destroy();
      });

      nodeStream.on("error", (err) => {
        if (!res.headersSent) next(err);
        else res.end();
      });

      nodeStream.pipe(res);
    } catch (err) {
      next(err);
    }
  };
}
