import { SecurityAlert } from "../../src/types";

/**
 * Calculates threat risk score and risk level from an array of security alerts.
 */
export function calculateRisk(alerts: SecurityAlert[]): {
  score: number;
  riskLevel: "Low" | "Medium" | "High" | "Critical";
} {
  let score = 0;

  for (const alert of alerts) {
    const sev = (alert.severity || "").toUpperCase();
    if (sev === "LOW") {
      score += 10;
    } else if (sev === "MEDIUM") {
      score += 20;
    } else if (sev === "HIGH") {
      score += 40;
    } else if (sev === "CRITICAL") {
      score += 60;
    }
  }

  // Cap score at 100 for gauge visualization in UI, while preserving raw bounds for risk categories.
  const displayScore = Math.min(100, score);

  let riskLevel: "Low" | "Medium" | "High" | "Critical" = "Low";
  if (score <= 20) {
    riskLevel = "Low";
  } else if (score <= 50) {
    riskLevel = "Medium";
  } else if (score <= 80) {
    riskLevel = "High";
  } else {
    riskLevel = "Critical";
  }

  return {
    score: displayScore,
    riskLevel,
  };
}
