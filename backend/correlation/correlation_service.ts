import { SecurityAlert } from "../../src/types";
import { evaluateRules } from "./rules";
import { calculateRisk } from "./risk_engine";
import { detectCampaign } from "./campaign_engine";
import { buildTimeline } from "./timeline_builder";

export interface CorrelationResult {
  attackType: string;
  campaignName: string;
  confidence: number;
  score: number;
  riskLevel: "Low" | "Medium" | "High" | "Critical";
  timeline: string[];
}

/**
 * Main Orchestrator of the Threat Correlation Engine.
 * Correlates a set of security alerts and returns detailed threat intelligence campaign metrics.
 */
export function correlateAlerts(alerts: SecurityAlert[]): CorrelationResult {
  if (!alerts || alerts.length === 0) {
    return {
      attackType: "Unknown Activity",
      campaignName: "Generic Campaign",
      confidence: 0,
      score: 0,
      riskLevel: "Low",
      timeline: [],
    };
  }

  // 1. Run Rules Engine
  const attackType = evaluateRules(alerts);

  // 2. Run Campaign Detection Engine
  const campaignInfo = detectCampaign(alerts);

  // 3. Run Risk Scoring Engine
  const riskInfo = calculateRisk(alerts);

  // 4. Run Timeline Builder
  const timeline = buildTimeline(alerts);

  return {
    attackType,
    campaignName: campaignInfo.campaignName,
    confidence: campaignInfo.confidence,
    score: riskInfo.score,
    riskLevel: riskInfo.riskLevel,
    timeline,
  };
}
