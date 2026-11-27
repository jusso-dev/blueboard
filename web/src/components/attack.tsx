import { useMemo, useState } from "react";
import { Link } from "react-router";
import type { ActionTarget } from "../lib/actions";
import { useLiveQuery } from "../lib/api";
import {
  filterTimeline, KIND_LABEL, layoutGraph, NODE_GLYPH, refLink, targetsForNode,
  type AttackGraph, type GraphNode, type Timeline, type TimelineEvent,
} from "../lib/attack";
import { RequestActionButton } from "./request-action";
import { Button, cx, Empty, ErrorLine, Input, Tag } from "./ui";

/**
 * Attack timeline and attack graph for an incident (GET /incidents/{id}/timeline and /graph). Both are built by the
 * board from Defender evidence, board messages and actions; never model-written. Clicking a node filters the timeline
 * to it and offers the request-action shortcuts for that entity. Plain SVG, no chart library.
 */
export function AttackViews({ incident, targets, onOpenThread }: { incident: string; targets: ActionTarget[]; onOpenThread: (id: string) => void }) {
  const { data: timeline, error: tErr } = useLiveQuery<Timeline>(`/incidents/${encodeURIComponent(incident)}/timeline?limit=1000`);
  const { data: graph, error: gErr } = useLiveQuery<AttackGraph>(`/incidents/${encodeURIComponent(incident)}/graph`);
  const [selected, setSelected] = useState<string | null>(null);
  const node = graph?.nodes.find((n) => n.id === selected) ?? null;

  return (
    <section aria-label="Attack timeline and graph" className="grid gap-4 px-6 py-3 max-sm:px-4 xl:grid-cols-[minmax(0,6fr)_minmax(0,5fr)]">
      <div className="min-w-0">
        {gErr ? <ErrorLine>{gErr.message}</ErrorLine> : graph ? (
          <GraphPanel graph={graph} selected={selected} onSelect={(id) => setSelected(id === selected ? null : id)} />
        ) : null}
        {node && <NodeDetail node={node} targets={targets} incident={incident} onClear={() => setSelected(null)} />}
      </div>
      <div className="min-w-0">
        {tErr ? <ErrorLine>{tErr.message}</ErrorLine> : timeline ? (
          <TimelinePanel timeline={timeline} node={node} onClearNode={() => setSelected(null)} onOpenThread={onOpenThread} />
        ) : null}
      </div>
    </section>
  );
}

const KIND_TONE: Record<TimelineEvent["kind"], "neutral" | "accent" | "critical" | "warning" | "good"> = {
  alert: "critical", evidence: "warning", finding: "accent", ioc: "accent", verdict: "good", action: "neutral",
};

function TimelinePanel({ timeline, node, onClearNode, onOpenThread }: { timeline: Timeline; node: GraphNode | null; onClearNode: () => void; onOpenThread: (id: string) => void }) {
  const [text, setText] = useState("");
  const [kinds, setKinds] = useState<Set<string>>(new Set());
  const rows = useMemo(() => filterTimeline(timeline.events, { keys: node?.keys ?? null, text, kinds }), [timeline, node, text, kinds]);
  const toggle = (k: string) => setKinds((prev) => {
    const next = new Set(prev);
    if (next.has(k)) next.delete(k);
    else next.add(k);
    return next;
  });

  return (
    <div>
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <h2 className="label text-ink-2">Timeline ({rows.length}{rows.length !== timeline.events.length ? ` of ${timeline.events.length}` : ""})</h2>
        <div role="group" aria-label="Filter by source" className="flex flex-wrap gap-1">
          {(Object.keys(KIND_LABEL) as TimelineEvent["kind"][]).map((k) => (
            <button key={k} type="button" aria-pressed={kinds.has(k)} onClick={() => toggle(k)}
              className={cx("rounded-[4px] border px-1.5 text-meta", kinds.has(k) ? "border-accent text-accent" : "border-rule text-muted hover:text-ink")}>
              {KIND_LABEL[k]}
            </button>
          ))}
        </div>
        <Input aria-label="Filter timeline by entity or text" placeholder="Entity or text" value={text} onChange={(e) => setText(e.target.value)} className="h-7 w-44" />
        {node && (
          <Button size="sm" variant="ghost" onClick={onClearNode}>
            Showing {node.label} ✕
          </Button>
        )}
      </div>
      {rows.length === 0 ? (
        <p className="text-ui text-faint">No events match.</p>
      ) : (
        <ol className="max-h-[52dvh] space-y-0 overflow-y-auto border-l border-rule" aria-label="Attack timeline">
          {rows.map((e) => (
            <li key={e.id} className="relative py-1.5 pl-4">
              <span aria-hidden className={cx("absolute -left-[4px] top-3 size-2 rounded-full",
                e.lane === "attack" ? "bg-critical" : e.lane === "detection" ? "bg-warning" : "bg-accent")} />
              <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
                <time dateTime={e.ts} className="label tnum text-ink-2" title={e.ts}>{new Date(e.ts).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" })}</time>
                <Tag tone={KIND_TONE[e.kind]}>{KIND_LABEL[e.kind]}</Tag>
                {e.reported && (
                  <Tag tone={e.in_evidence ? "neutral" : "warning"} title={e.in_evidence ? "Reported by a participant; the entity appears in incident evidence" : "Reported by a participant; the entity is NOT in incident evidence"}>
                    reported{e.in_evidence === false ? " · not in evidence" : ""}
                  </Tag>
                )}
              </div>
              <p className="text-ui [overflow-wrap:anywhere]">{e.action}</p>
              <p className="text-meta text-muted [overflow-wrap:anywhere]">
                {e.entities.length > 0 && <span className="font-mono">{e.entities.slice(0, 4).join(", ")}{e.entities.length > 4 ? ", …" : ""} · </span>}
                {e.source}
                {e.reported_by.length > 0 && <> · by {e.reported_by.map((h) => `@${h}`).join(", ")}</>}
                {e.refs.map((r, i) => {
                  const l = refLink(r, e.thread_id);
                  if (!l) return null;
                  return (
                    <span key={`${r.type}-${r.id}-${i}`}>
                      {" · "}
                      {"to" in l ? (
                        <Link to={l.to} className="text-accent hover:underline">{l.label}</Link>
                      ) : (
                        <button type="button" onClick={() => onOpenThread(l.thread)} className="text-accent hover:underline">{l.label}</button>
                      )}
                    </span>
                  );
                })}
              </p>
            </li>
          ))}
        </ol>
      )}
      <p className="mt-2 text-meta text-faint">{timeline.notice}{timeline.truncated ? " Older events beyond the limit are not shown." : ""}</p>
    </div>
  );
}

const VERDICT_COLOR: Record<string, string> = {
  malicious: "var(--color-critical)",
  suspicious: "var(--color-warning)",
  benign: "var(--color-good)",
};

function GraphPanel({ graph, selected, onSelect }: { graph: AttackGraph; selected: string | null; onSelect: (id: string) => void }) {
  const layout = useMemo(() => layoutGraph(graph), [graph]);
  const pos = useMemo(() => new Map(layout.nodes.map((n) => [n.id, n])), [layout]);
  const linked = useMemo(() => {
    if (!selected) return null;
    const s = new Set([selected]);
    for (const e of graph.edges) {
      if (e.from === selected) s.add(e.to);
      if (e.to === selected) s.add(e.from);
    }
    return s;
  }, [graph, selected]);
  if (graph.nodes.length === 0) return <Empty title="No entities in the evidence yet" />;

  return (
    <div>
      <div className="mb-2 flex flex-wrap items-center gap-x-3 gap-y-1">
        <h2 className="label text-ink-2">Attack graph ({graph.nodes.length} entities, {graph.edges.length} links)</h2>
        <span className="text-meta text-muted">
          <Legend color="var(--color-critical)" label="malicious / compromised" /> <Legend color="var(--color-warning)" label="suspicious" />{" "}
          <Legend color="var(--color-accent)" label="action pending" dashed /> <Legend color="var(--color-good)" label="protected" ring />
        </span>
      </div>
      <div className="max-h-[52dvh] overflow-auto rounded-[var(--radius-control)] border border-rule bg-paper-2">
        <svg role="img" aria-label="Attack graph: select an entity to filter the timeline" width={layout.width + 120} height={layout.height} className="block">
          <defs>
            <marker id="bb-arrow" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 0 L 10 5 L 0 10 z" fill="var(--color-rule-strong)" />
            </marker>
          </defs>
          {graph.edges.map((e) => {
            const a = pos.get(e.from);
            const b = pos.get(e.to);
            if (!a || !b) return null;
            const dim = linked && !(linked.has(e.from) && linked.has(e.to));
            const dx = b.x - a.x, dy = b.y - a.y, len = Math.hypot(dx, dy) || 1;
            const r = 16;
            return (
              <g key={`${e.from}-${e.to}-${e.relation}`} opacity={dim ? 0.15 : 1}>
                <line x1={a.x + (dx / len) * r} y1={a.y + (dy / len) * r} x2={b.x - (dx / len) * r} y2={b.y - (dy / len) * r}
                  stroke="var(--color-rule-strong)" strokeWidth={1.25} strokeDasharray={e.inferred ? "4 3" : undefined} markerEnd="url(#bb-arrow)">
                  <title>{`${a.label} ${e.relation} ${b.label}${e.inferred ? " (inferred)" : ""}`}</title>
                </line>
                {!dim && linked && (
                  <text x={(a.x + b.x) / 2} y={(a.y + b.y) / 2 - 4} textAnchor="middle" className="fill-[var(--color-muted)] text-[10px]">{e.relation}</text>
                )}
              </g>
            );
          })}
          {layout.nodes.map((n) => {
            const dim = linked && !linked.has(n.id);
            const bad = n.compromised || n.verdict === "malicious";
            const stroke = bad ? VERDICT_COLOR.malicious : n.verdict ? VERDICT_COLOR[n.verdict] : "var(--color-rule-strong)";
            return (
              <g key={n.id} transform={`translate(${n.x},${n.y})`} opacity={dim ? 0.3 : 1} role="button" tabIndex={0}
                aria-label={`${n.kind} ${n.label}${n.verdict ? `, ${n.verdict}` : ""}${n.compromised ? ", compromised" : ""}${n.protected ? ", protected" : ""}`}
                aria-pressed={selected === n.id}
                onClick={() => onSelect(n.id)} onKeyDown={(ev) => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); onSelect(n.id); } }}
                className="cursor-pointer focus:outline-none">
                {n.protected && <circle r={21} fill="none" stroke="var(--color-good)" strokeWidth={2} />}
                {n.pending_actions.length > 0 && <circle r={24} fill="none" stroke="var(--color-accent)" strokeWidth={1.5} strokeDasharray="3 3" />}
                <circle r={16} fill={selected === n.id ? "var(--color-accent-soft)" : "var(--color-paper-3)"} stroke={stroke} strokeWidth={bad ? 2.5 : 1.5}
                  strokeDasharray={n.in_evidence ? undefined : "2 2"} />
                <text textAnchor="middle" dy="0.35em" className="fill-[var(--color-ink)] text-[10px] font-medium">{NODE_GLYPH[n.kind]}</text>
                <text x={22} dy="0.35em" className="fill-[var(--color-ink-2)] text-[11px]">{n.label.length > 26 ? `${n.label.slice(0, 25)}…` : n.label}</text>
                <title>{`${n.kind}: ${n.label}`}</title>
              </g>
            );
          })}
        </svg>
      </div>
      <p className="mt-1 text-meta text-faint">{graph.notice} Dashed links are inferred; dashed outlines are entities only in board IOCs.{graph.truncated ? " Large graph: some entities are not shown." : ""}</p>
    </div>
  );
}

function Legend({ color, label, dashed, ring }: { color: string; label: string; dashed?: boolean; ring?: boolean }) {
  return (
    <span className="inline-flex items-center gap-1 whitespace-nowrap">
      <svg width="10" height="10" aria-hidden><circle cx="5" cy="5" r="4" fill={ring ? "none" : "none"} stroke={color} strokeWidth={2} strokeDasharray={dashed ? "2 1" : undefined} /></svg>
      {label}
    </span>
  );
}

function NodeDetail({ node, targets, incident, onClear }: { node: GraphNode; targets: ActionTarget[]; incident: string; onClear: () => void }) {
  const nodeTargets = useMemo(() => targetsForNode(node, targets), [node, targets]);
  return (
    <div className="mt-2 rounded-[var(--radius-control)] border border-rule p-3" aria-live="polite">
      <div className="flex flex-wrap items-center gap-2">
        <span className="label text-ink-2">{node.kind.replace("_", " ")}</span>
        <span className="font-mono text-ui [overflow-wrap:anywhere]">{node.label}</span>
        {node.verdict && <Tag tone={node.verdict === "malicious" ? "critical" : node.verdict === "suspicious" ? "warning" : "good"}>{node.verdict}</Tag>}
        {node.compromised && <Tag tone="critical">compromised</Tag>}
        {node.protected && <Tag tone="good" title={node.protected_as ?? "On a policy protected list (admins see which entry)"}>protected{node.protected_as ? `: ${node.protected_as}` : ""}</Tag>}
        {!node.in_evidence && <Tag tone="warning" title="Only in board IOC messages, not in Defender evidence">not in evidence</Tag>}
        <Button size="sm" variant="ghost" onClick={onClear}>Clear</Button>
      </div>
      {(node.pending_actions.length > 0 || node.executed_actions.length > 0) && (
        <p className="mt-1 text-meta text-muted">
          {node.pending_actions.length > 0 && <>Pending: {node.pending_actions.join(", ")}. </>}
          {node.executed_actions.length > 0 && <>Done: {node.executed_actions.join(", ")}.</>}
        </p>
      )}
      {node.keys.length > 1 && <p className="mt-1 text-meta text-muted [overflow-wrap:anywhere]">Also known as <span className="font-mono">{node.keys.filter((k) => k !== node.label).join(", ")}</span></p>}
      <div className="mt-2 flex flex-wrap items-center gap-2">
        {nodeTargets.length > 0 ? (
          <RequestActionButton targets={nodeTargets} incident={incident} size="sm" label={`Request action on ${node.label.length > 24 ? "this entity" : node.label}`} />
        ) : (
          <span className="text-meta text-faint">No brokered action targets this kind of entity.</span>
        )}
        {node.protected && <span className="text-meta text-warning">Policy will refuse destructive actions on a protected entity.</span>}
      </div>
    </div>
  );
}
