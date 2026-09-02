import { useEffect, useState } from "react";
import { api } from "../api/client";
import type { DetectorInfo } from "../api/types";
import { ErrorBanner, Spinner } from "../components/common";

/** What each detector catches, and what it misses.
 *
 * Served from the detectors' own declarations rather than duplicated here, so
 * the limitations shown to a user cannot drift from the code that produces the
 * findings.
 */
export function Detectors() {
  const [detectors, setDetectors] = useState<DetectorInfo[] | null>(null);
  const [error, setError] = useState<unknown>(null);

  useEffect(() => {
    api.detectors().then(setDetectors).catch(setError);
  }, []);

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Detection engines</h1>
          <p>
            What each detector looks for, and where it is known to be wrong. No detector here
            is exact; knowing which way each one fails is what makes a finding actionable.
          </p>
        </div>
      </div>

      <ErrorBanner error={error} />
      {detectors === null ? (
        <Spinner />
      ) : (
        <div className="grid cols-2">
          {detectors.map((detector) => (
            <div className="card" key={detector.name}>
              <h2>
                {detector.name.replace(/_/g, " ")}
                {!detector.requires_network && <span className="chip" style={{ marginLeft: 8 }}>offline</span>}
              </h2>
              <p style={{ marginTop: 0 }}>{detector.description}</p>

              <h4 style={{ fontSize: 11, textTransform: "uppercase", letterSpacing: "0.06em",
                           color: "var(--medium)", marginBottom: 6 }}>
                May report things that are fine
              </h4>
              <ul style={{ margin: 0, paddingLeft: 18, color: "var(--text-dim)" }}>
                {detector.known_false_positives.map((item, index) => (
                  <li key={index}>{item}</li>
                ))}
              </ul>

              <h4 style={{ fontSize: 11, textTransform: "uppercase", letterSpacing: "0.06em",
                           color: "var(--critical)", marginBottom: 6, marginTop: 14 }}>
                Will not catch
              </h4>
              <ul style={{ margin: 0, paddingLeft: 18, color: "var(--text-dim)" }}>
                {detector.known_false_negatives.map((item, index) => (
                  <li key={index}>{item}</li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      )}
    </>
  );
}
