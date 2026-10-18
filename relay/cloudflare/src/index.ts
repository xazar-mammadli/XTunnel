import { DurableObject } from "cloudflare:workers";

interface Limiter {
  limit(options: { key: string }): Promise<{ success: boolean }>;
}

interface RelayEnv {
  ROOMS: DurableObjectNamespace<Room>;
  LIMITER?: Limiter;
  UNPAIRED_TTL_MS?: string;
  PAIRED_TTL_MS?: string;
}

type Role = "host" | "join";

interface Attachment {
  role: Role;
  room: string;
  messages: number;
  active: boolean;
  paired: boolean;
}

interface Envelope {
  type: string;
  room?: string;
  body?: string;
  error?: string;
}

const opHeader = "X-Xtunnel-Op";
const roomHeader = "X-Xtunnel-Room";
const nameplatePattern = /^[0-9]{1,5}$/;
const createAttempts = 12;
const maxMessagesPerSocket = 16;
const maxMessageBytes = 32 * 1024;
const defaultUnpairedTtlMs = 10 * 60 * 1000;
const defaultPairedTtlMs = 5 * 60 * 1000;

export default {
  async fetch(request, env): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/healthz") {
      return new Response("ok");
    }
    if (url.pathname !== "/ws") {
      return new Response("not found", { status: 404 });
    }
    if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
      return new Response("expected a WebSocket upgrade", { status: 426 });
    }
    if (env.LIMITER) {
      const key = request.headers.get("CF-Connecting-IP") ?? "unknown";
      const { success } = await env.LIMITER.limit({ key });
      if (!success) {
        return new Response("rate limited", { status: 429 });
      }
    }

    const op = url.searchParams.get("op");
    if (op === "join") {
      const room = url.searchParams.get("room") ?? "";
      if (!nameplatePattern.test(room)) {
        return new Response("invalid room", { status: 400 });
      }
      return roomStub(env, room).fetch(forward(request, "join", room));
    }
    if (op === "create") {
      for (let attempt = 0; attempt < createAttempts; attempt++) {
        const room = randomNameplate(attempt);
        const response = await roomStub(env, room).fetch(forward(request, "create", room));
        if (response.status !== 409) {
          return response;
        }
      }
      return new Response("no free room, try again", { status: 503 });
    }
    return new Response("unknown op", { status: 400 });
  },
} satisfies ExportedHandler<RelayEnv>;

export class Room extends DurableObject<RelayEnv> {
  async fetch(request: Request): Promise<Response> {
    const op = request.headers.get(opHeader);
    const room = request.headers.get(roomHeader) ?? "";
    const host = this.host();

    if (op === "create") {
      if (host) {
        return new Response("room taken", { status: 409 });
      }
      for (const stale of this.ctx.getWebSockets("join")) {
        close(stale, 1000, "room closed");
      }
      await this.ctx.storage.setAlarm(Date.now() + ttl(this.env.UNPAIRED_TTL_MS, defaultUnpairedTtlMs));
      return this.accept("host", room);
    }

    if (!host) {
      return new Response("no such room (codes are one-time and expire)", { status: 404 });
    }
    if (attachment(host).paired) {
      return new Response("room is full", { status: 409 });
    }
    return this.accept("join", room);
  }

  async webSocketMessage(ws: WebSocket, data: string | ArrayBuffer): Promise<void> {
    const att = attachment(ws);
    att.messages++;
    const size = typeof data === "string" ? data.length : data.byteLength;
    if (att.messages > maxMessagesPerSocket || size > maxMessageBytes) {
      this.drop(ws, att, "message limit exceeded");
      return;
    }
    ws.serializeAttachment(att);

    const env = parse(data);
    if (!env) {
      this.drop(ws, att, "malformed envelope");
      return;
    }
    switch (env.type) {
      case "create":
        this.onCreate(ws, att);
        break;
      case "join":
        await this.onJoin(ws, att, env);
        break;
      case "msg":
        this.onMsg(ws, att, env);
        break;
    }
  }

  async webSocketClose(ws: WebSocket): Promise<void> {
    this.leave(ws, attachment(ws), 1000, "bye");
  }

  async webSocketError(ws: WebSocket): Promise<void> {
    this.leave(ws, attachment(ws), 1011, "error");
  }

  async alarm(): Promise<void> {
    for (const ws of this.ctx.getWebSockets()) {
      send(ws, { type: "error", error: "room expired" });
      close(ws, 1000, "room expired");
    }
  }

  private accept(role: Role, room: string): Response {
    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    this.ctx.acceptWebSocket(server, [role]);
    const att: Attachment = { role, room, messages: 0, active: role === "host", paired: false };
    server.serializeAttachment(att);
    return new Response(null, { status: 101, webSocket: client });
  }

  private host(): WebSocket | undefined {
    return this.ctx.getWebSockets("host")[0];
  }

  private onCreate(ws: WebSocket, att: Attachment): void {
    if (att.role !== "host") {
      this.drop(ws, att, "expected join");
      return;
    }
    send(ws, { type: "created", room: att.room });
  }

  private async onJoin(ws: WebSocket, att: Attachment, env: Envelope): Promise<void> {
    if (att.role !== "join" || att.active || env.room !== att.room) {
      this.drop(ws, att, "invalid room code");
      return;
    }
    const host = this.host();
    if (!host) {
      this.drop(ws, att, "no such room (codes are one-time and expire)");
      return;
    }
    const hostAtt = attachment(host);
    if (hostAtt.paired) {
      this.drop(ws, att, "room is full");
      return;
    }
    hostAtt.paired = true;
    host.serializeAttachment(hostAtt);
    att.active = true;
    ws.serializeAttachment(att);
    await this.ctx.storage.setAlarm(Date.now() + ttl(this.env.PAIRED_TTL_MS, defaultPairedTtlMs));
    send(host, { type: "peer" });
    send(ws, { type: "joined" });
  }

  private onMsg(ws: WebSocket, att: Attachment, env: Envelope): void {
    if (!att.active || typeof env.body !== "string") {
      this.drop(ws, att, "not in a room");
      return;
    }
    const peer = this.peerOf(att);
    if (!peer) {
      send(ws, { type: "error", error: "peer not connected" });
      return;
    }
    send(peer, { type: "msg", body: env.body });
  }

  private peerOf(att: Attachment): WebSocket | undefined {
    if (att.role === "host") {
      return this.ctx.getWebSockets("join").find((ws) => attachment(ws).active);
    }
    return this.host();
  }

  private drop(ws: WebSocket, att: Attachment, error: string): void {
    send(ws, { type: "error", error });
    this.leave(ws, att, 1008, error);
  }

  private leave(ws: WebSocket, att: Attachment, code: number, reason: string): void {
    close(ws, code, reason);
    if (att.role === "host") {
      for (const other of this.ctx.getWebSockets()) {
        if (other !== ws) {
          send(other, { type: "peer-left" });
          close(other, 1000, "room closed");
        }
      }
      void this.ctx.storage.deleteAlarm();
      return;
    }
    if (att.active) {
      const host = this.host();
      if (host) {
        send(host, { type: "peer-left" });
      }
    }
  }
}

function roomStub(env: RelayEnv, room: string): DurableObjectStub<Room> {
  return env.ROOMS.get(env.ROOMS.idFromName(room));
}

function forward(request: Request, op: string, room: string): Request {
  const headers = new Headers(request.headers);
  headers.set(opHeader, op);
  headers.set(roomHeader, room);
  return new Request(request.url, { method: request.method, headers });
}

function randomNameplate(attempt: number): string {
  const span = attempt < 8 ? 999 : 99999;
  const value = crypto.getRandomValues(new Uint32Array(1))[0];
  return String(1 + (value % span));
}

function attachment(ws: WebSocket): Attachment {
  return ws.deserializeAttachment() as Attachment;
}

function parse(data: string | ArrayBuffer): Envelope | undefined {
  try {
    const value: unknown = JSON.parse(typeof data === "string" ? data : new TextDecoder().decode(data));
    if (value && typeof value === "object" && typeof (value as Envelope).type === "string") {
      return value as Envelope;
    }
  } catch {
    return undefined;
  }
  return undefined;
}

function send(ws: WebSocket, env: Envelope): void {
  try {
    ws.send(JSON.stringify(env));
  } catch {
    return;
  }
}

function close(ws: WebSocket, code: number, reason: string): void {
  try {
    ws.close(code, reason);
  } catch {
    return;
  }
}

function ttl(value: string | undefined, fallback: number): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}
