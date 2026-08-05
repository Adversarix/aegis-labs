// aegis store — the human/custodian path to the munitions store. This is where
// arm/export/dispose live (munitions-custody-policy.md §6): the harness cannot
// self-authorize them, so they are NOT agent tools. The CLI supplies the human
// authorization {role, actor} that the store library requires.
import { PATHS } from "./config.js";

async function open(cfg) {
  const { openStore } = await import(PATHS.storeLib);
  return openStore(cfg.store_dir, { key: cfg.store_key });
}

export async function storeCommand(cfg, sub, args) {
  const store = await open(cfg);
  switch (sub) {
    case "list": {
      const rows = store.list();
      if (!rows.length) return "no munitions in the store";
      return rows.map((m) => `${m.id}  ${m.custody_state.padEnd(9)} ${m.exploitation.level.padEnd(9)} ` +
        `${m.ownership}/${m.disclosure_status}  events=${m.events}`).join("\n");
    }
    case "show": {
      if (!args.id) throw new Error("usage: aegis store show <id>");
      return JSON.stringify(store.list().find((m) => m.id === args.id) || { error: `no munition ${args.id}` }, null, 2);
    }
    case "verify": {
      if (!args.id) throw new Error("usage: aegis store verify <id>");
      return JSON.stringify(store.verify(args.id), null, 2);
    }
    case "dispose": {
      if (!args.id) throw new Error("usage: aegis store dispose <id> --role <role> --actor <name> [--reason <text>]");
      if (!args.role || !args.actor) throw new Error("dispose requires a human authorization: --role and --actor");
      const r = store.dispose(args.id, { authorization: { role: args.role, actor: args.actor }, reason: args.reason || "cli disposal" });
      return `disposed ${r.id} (shredded=${r.shredded}); ledger closed`;
    }
    default:
      throw new Error(`unknown store subcommand '${sub}' (list | show | verify | dispose)`);
  }
}
