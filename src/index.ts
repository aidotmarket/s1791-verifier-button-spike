// S1791 spike: does a Deploy to Cloudflare button deploy a Container verifier
// skeleton into a seller's own account? Reads no data. Every route needs the
// SPIKE_SECRET the deployer chose.
import { Container, getContainer } from "@cloudflare/containers";
export { ContainerProxy } from "@cloudflare/containers";

interface Env {
  SPIKE: DurableObjectNamespace<SpikeVerifier>;
  DATA: R2Bucket;
  SPIKE_SECRET: string;
}

export class SpikeVerifier extends Container<Env> {
  defaultPort = 8080;
  sleepAfter = "5m";
  enableInternet = false;
  allowedHosts = ["api.ai.market"];

  private log(kind: string, detail = "") {
    this.ctx.storage.sql.exec(
      "CREATE TABLE IF NOT EXISTS spike_events (at TEXT, kind TEXT, detail TEXT)");
    this.ctx.storage.sql.exec(
      "INSERT INTO spike_events VALUES (?, ?, ?)", new Date().toISOString(), kind, detail);
  }
  override onStart() { this.log("container_start"); }
  async cron() { this.log("cron"); await this.schedule(1, "tick", "from_cron"); }
  async runNow() { this.log("run_now"); await this.schedule(1, "tick", "from_run_now"); }
  async tick(payload: string) { this.log("scheduled_tick", payload); }
  async events() {
    this.log("status_read");
    return this.ctx.storage.sql.exec("SELECT * FROM spike_events ORDER BY at").toArray();
  }
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    if (!env.SPIKE_SECRET || req.headers.get("authorization") !== `Bearer ${env.SPIKE_SECRET}`)
      return new Response("unauthorized", { status: 401 });
    const stub = getContainer(env.SPIKE, "spike");
    const path = new URL(req.url).pathname;
    if (path === "/status") return Response.json(await stub.events());
    if (path === "/run-now") { await stub.runNow(); return new Response(null, { status: 202 }); }
    if (path === "/container") return stub.fetch(new Request("http://container/"));
    if (path === "/tls") return stub.fetch(new Request("http://container/tls-check"));
    if (path === "/r2") return Response.json({ binding: !!env.DATA, listed: (await env.DATA.list({ limit: 1 })).objects.length });
    return new Response("not found", { status: 404 });
  },
  async scheduled(_c: ScheduledController, env: Env) {
    await getContainer(env.SPIKE, "spike").cron();
  },
} satisfies ExportedHandler<Env>;
