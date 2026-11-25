import { Readable } from "node:stream";
import type { ReadableStream as NodeWebReadableStream } from "node:stream/web";
import type { Response as ExpressResponse, RequestHandler } from "express";
import type { McpHttpHandler } from "@modelcontextprotocol/server";
import type { AuthenticatedRequest } from "../middleware/authMiddleware.js";

/**
 * Adapts a Web Standard `McpHttpHandler` (`createMcpHandler`) onto an Express route.
 * Mount BEFORE `express.json()` so the SDK reads raw request bytes and enforces size/content-type checks.
 */
export function expressMcpHandler(handler: McpHttpHandler): RequestHandler {
  return async (req: AuthenticatedRequest, res: ExpressResponse, next) => {
    try {
      const protocol = req.protocol || "http";
      const host = req.get("host") || "localhost";
      const url = new URL(req.originalUrl, `${protocol}://${host}`);

      const headers = new Headers();
      for (const [key, value] of Object.entries(req.headers)) {
        if (value === undefined) continue;
        if (Array.isArray(value)) {
          for (const item of value) {
            headers.append(key, item);
          }
        } else {
          headers.set(key, value);
        }
      }

      const hasBody = req.method !== "GET" && req.method !== "HEAD";
      const init: RequestInit & { duplex?: "half" } = {
        method: req.method,
        headers,
      };
      if (hasBody) {
        init.body = Readable.toWeb(req) as unknown as NonNullable<RequestInit["body"]>;
        init.duplex = "half";
      }

      const webRequest = new globalThis.Request(url, init);
      const webResponse = await handler.fetch(webRequest, {
        ...(req.authInfo !== undefined ? { authInfo: req.authInfo } : {}),
      });

      res.status(webResponse.status);
      webResponse.headers.forEach((value, key) => {
        res.setHeader(key, value);
      });

      if (!webResponse.body) {
        res.end();
        return;
      }

      res.flushHeaders();
      const nodeStream = Readable.fromWeb(
        webResponse.body as unknown as NodeWebReadableStream<Uint8Array>
      );

      req.on("close", () => {
        if (!res.writableEnded) {
          nodeStream.destroy();
        }
      });

      nodeStream.on("error", (err) => {
        if (!res.headersSent) {
          next(err);
        } else {
          res.end();
        }
      });

      nodeStream.pipe(res);
    } catch (err) {
      next(err);
    }
  };
}
