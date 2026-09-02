import { useState } from "react";
import type { TreeNode } from "../api/types";
import { Empty } from "./common";

/** Dependency tree with findings overlaid.
 *
 * Nodes carrying findings are highlighted and expanded by default, so opening
 * the view lands the reader on the problem rather than on a wall of clean
 * packages they have to hunt through.
 */
export function DependencyTree({ nodes }: { nodes: TreeNode[] }) {
  const [showClean, setShowClean] = useState(true);

  if (!nodes.length) return <Empty>No dependency tree was recorded for this scan.</Empty>;

  const visible = showClean ? nodes : nodes.filter(hasFindings);

  return (
    <div>
      <div className="filters">
        <label style={{ display: "flex", alignItems: "center", gap: 6, margin: 0 }}>
          <input
            type="checkbox"
            style={{ width: "auto" }}
            checked={showClean}
            onChange={(e) => setShowClean(e.target.checked)}
          />
          Show dependencies with no findings
        </label>
      </div>
      {visible.length === 0 ? (
        <Empty>No dependency in this tree has findings.</Empty>
      ) : (
        <div className="tree">
          <ul>
            {visible.map((node) => (
              <TreeBranch key={node.key} node={node} showClean={showClean} />
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function hasFindings(node: TreeNode): boolean {
  return node.finding_count > 0 || node.children.some(hasFindings);
}

function TreeBranch({ node, showClean }: { node: TreeNode; showClean: boolean }) {
  const children = showClean ? node.children : node.children.filter(hasFindings);
  // Expand the path to a problem automatically; collapse everything else.
  const [open, setOpen] = useState(() => hasFindings(node));

  return (
    <li>
      <span className={`node${node.finding_count ? " has-findings" : ""}`}>
        {children.length > 0 ? (
          <span
            className="toggle"
            role="button"
            tabIndex={0}
            onClick={() => setOpen((v) => !v)}
            onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && setOpen((v) => !v)}
            aria-label={open ? "Collapse" : "Expand"}
          >
            {open ? "▾" : "▸"}
          </span>
        ) : (
          <span className="toggle" />
        )}
        <span className="pkg-name">{node.name}</span>
        <span className="pkg-version">@{node.version}</span>
        {node.is_dev && <span className="dev-tag">dev</span>}
        {node.finding_count > 0 && node.severity && (
          <span className={`badge sev-${node.severity}`}>
            {node.finding_count} {node.severity}
          </span>
        )}
      </span>
      {open && children.length > 0 && (
        <ul>
          {children.map((child) => (
            <TreeBranch key={child.key} node={child} showClean={showClean} />
          ))}
        </ul>
      )}
    </li>
  );
}
