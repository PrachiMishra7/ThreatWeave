import driver from "./neo4j";

export async function saveThreatGraph(data: any) {
  const session = driver.session();
try {
 const campaignName =
  data.campaignProposedName ||
  data.threat_campaign?.name ||
  "Unknown Campaign";

console.log("CAMPAIGN NAME:", campaignName);
console.log("DATA:", JSON.stringify(data, null, 2));

  const threatActor =
    data.threatActor ||
    data.threat_campaign?.threatActor ||
    data.threat_campaign?.threat_actor ||
    null;
  const alerts =
    data.extractedAlerts ||
    data.parsed_alerts ||
    data.security_incidents ||
    [];
  console.log("ALERT COUNT:", alerts.length);

  const confidence =
    data.confidence ||
    data.threat_campaign?.confidence ||
    85;

  const riskScore =
    data.riskScore ||
    data.threat_campaign?.riskScore ||
    data.threat_campaign?.risk_score ||
    (alerts.length > 0 ? Math.min(60 + alerts.length * 5, 95) : 75);

  const status =
    data.status ||
    data.threat_campaign?.status ||
    "active";

  const initialAccess =
    data.initialAccess ||
    data.threat_campaign?.initialAccess ||
    data.threat_campaign?.initial_access ||
    (alerts[0]?.title || "Under Analysis");

  const persistence =
    data.persistence ||
    data.threat_campaign?.persistence ||
    "Under Analysis";

  const lateralMovement =
    data.lateralMovement ||
    data.threat_campaign?.lateralMovement ||
    data.threat_campaign?.lateral_movement ||
    "Under Analysis";

  const targetSector =
    data.targetSector ||
    data.threat_campaign?.targetSector ||
    data.threat_campaign?.target_sector ||
    "Enterprise Infrastructure";

  const summary =
    data.explanation ||
    data.summary ||
    data.threat_campaign?.summary ||
    data.threat_campaign?.description ||
    "AI correlated threat campaign";

  const aiExplanation =
    data.explanation ||
    data.aiExplanation ||
    data.threat_campaign?.aiExplanation ||
    data.threat_campaign?.ai_explanation ||
    summary;

  const recommendedActionsRaw =
    data.recommendedActions ||
    data.threat_campaign?.recommendedActions ||
    data.threat_campaign?.recommended_actions;

  let recommendedActions: string[] = [];
  if (Array.isArray(recommendedActionsRaw)) {
    recommendedActions = recommendedActionsRaw;
  } else if (typeof recommendedActionsRaw === "string") {
    try {
      const parsed = JSON.parse(recommendedActionsRaw);
      if (Array.isArray(parsed)) {
        recommendedActions = parsed;
      } else {
        recommendedActions = [recommendedActionsRaw];
      }
    } catch {
      recommendedActions = [recommendedActionsRaw];
    }
  } else {
    recommendedActions = [
      "Isolate all affected systems from the production network.",
      "Review IOCs against external threat intelligence feeds.",
      "Escalate to Tier-3 analyst for manual correlation review."
    ];
  }

  const createdAt = new Date().toISOString();

  // Create Campaign Node
  await session.run(
    `
    MERGE (c:Campaign {name: $campaignName})
    SET c.threatActor = $threatActor,
        c.confidence = $confidence,
        c.riskScore = $riskScore,
        c.status = $status,
        c.initialAccess = $initialAccess,
        c.persistence = $persistence,
        c.lateralMovement = $lateralMovement,
        c.targetSector = $targetSector,
        c.summary = $summary,
        c.aiExplanation = $aiExplanation,
        c.recommendedActions = $recommendedActions,
        c.createdAt = COALESCE(c.createdAt, $createdAt)
    `,
    {
      campaignName,
      threatActor,
      confidence,
      riskScore,
      status,
      initialAccess,
      persistence,
      lateralMovement,
      targetSector,
      summary,
      aiExplanation,
      recommendedActions,
      createdAt,
    }
  );
    const tactics =
  data.threat_campaign?.mitre_attck_tactics || [];

for (const tactic of tactics) {

  const tacticName =
    typeof tactic === "string"
      ? tactic
      : tactic.tactic_name;

  await session.run(
    `
    MATCH (c:Campaign {name: $campaignName})

    MERGE (m:MitreTactic {name: $tacticName})

    MERGE (c)-[:USES_TACTIC]->(m)
    `,
    {
      campaignName,
      tacticName,
    }
  );
}

    // Create Alert Nodes
    if (alerts.length > 0) {
      for (const alert of alerts) {
  console.log("CREATING ALERT:", alert);
        await session.run(
          `
          MERGE (a:Alert {id: $id})
          SET a.title = $title,
              a.severity = $severity,
              a.sourceSystem = $sourceSystem

          WITH a
          MATCH (c:Campaign {name: $campaignName})
          MERGE (c)-[:CONTAINS]->(a)
          `,
         {
  campaignName,

  id:
    alert.id ||
    alert.alert_id ||
    alert.incident_id,

  title:
    alert.title ||
    alert.event_type ||
    alert.incident_type ||
    "Unknown Alert",

  severity: alert.severity || "MEDIUM",

  sourceSystem:
    alert.sourceSystem ||
    alert.source_system ||
    "Groq",
}
        );
    const ip =
  alert.source_ip ||
  alert.ip;

if (ip) {
  await session.run(
    `
    MERGE (i:IP {value: $value})

    WITH i
    MATCH (a:Alert {id: $alertId})

    MERGE (a)-[:USES]->(i)
    `,
    {
      value: ip,
      alertId:
        alert.id ||
        alert.alert_id ||
        alert.incident_id,
    }
  );
}

const domain =
  alert.destination_url ||
  alert.destination ||
  alert.website;

if (domain) {
  await session.run(
    `
    MERGE (d:Domain {value: $value})

    WITH d
    MATCH (a:Alert {id: $alertId})

    MERGE (a)-[:USES]->(d)
    `,
    {
      value: domain,
      alertId:
        alert.id ||
        alert.alert_id ||
        alert.incident_id,
    }
  );
}
    /*
const username =
  alert.username ||
  alert.destination_account ||
  alert.source_account;

if (username) {
  await session.run(
    `
    MERGE (u:User {value: $value})

    WITH u
    MATCH (a:Alert {id: $alertId})

    MERGE (a)-[:USES]->(u)
    `,
    {
      value: username,
      alertId: alert.id || alert.alert_id,
    }
  );
}
*/
        if (threatActor) {
  await session.run(
    `
    MERGE (t:ThreatActor {
      name: $threatActor
    })

    WITH t

    MATCH (c:Campaign {
      name: $campaignName
    })

    MERGE (t)-[:ATTRIBUTED_TO]->(c)
    `,
    {
      threatActor,
      campaignName,
    }
  );
}

        // Create IOC Nodes
               // Create IOC Nodes
        if (alert.iocs) {
  for (const ioc of alert.iocs) {
    const label =
      ["IP", "Domain", "User", "Hash"].includes(ioc.type)
        ? ioc.type
        : "IOC";

    console.log("Creating node:", label, ioc.value);

    await session.run(
              `
              MATCH (a:Alert {id: $alertId})

              MERGE (i:${label} {
                value: $value
              })

              MERGE (a)-[:USES]->(i)
              `,
              {
                alertId: alert.id,
                value: ioc.value,
              }
            );
          }
        }
    }



    // Create Correlation Relationships
    if (data.correlations) {
      for (const corr of data.correlations) {
        await session.run(
          `
          MATCH (a:Alert {id: $source})
          MATCH (b:Alert {id: $target})

          MERGE (a)-[:CORRELATES_TO {
            reason: $reason
          }]->(b)
          `,
          {
            source: corr.source,
            target: corr.target,
            reason: corr.reason,
          }
        );
      }
    }
 }
    console.log("Threat graph saved");
  } finally {
    await session.close();
  }
}

export async function getThreatGraph() {
  const session = driver.session();

  try {
    const result = await session.run(`
      MATCH (n)
      OPTIONAL MATCH (n)-[r]->(m)
      RETURN n, r, m
    `);

    const nodes = new Map();
    const edges: any[] = [];

    result.records.forEach((record) => {
      const n = record.get("n");
      const r = record.get("r");
      const m = record.get("m");

      if (n) {
        nodes.set(n.elementId, {
          id: n.elementId,
          label:
            n.properties.name ||
            n.properties.title ||
            n.properties.value ||
            n.properties.id,
          type: n.labels[0],
          properties: n.properties,
        });
      }

      if (m) {
        nodes.set(m.elementId, {
          id: m.elementId,
          label:
            m.properties.name ||
            m.properties.title ||
            m.properties.value ||
            m.properties.id,
          type: m.labels[0],
          properties: m.properties,
        });
      }

      if (r) {
        edges.push({
          id: r.elementId,
          source: r.startNodeElementId,
          target: r.endNodeElementId,
          label: r.type,
        });
      }
    });

    return {
      nodes: Array.from(nodes.values()),
      edges,
    };
  } finally {
    await session.close();
  }
}

export async function getNodes() {
  const session = driver.session();

  try {
    const result = await session.run(`
      MATCH (n)
      RETURN n
    `);

    return result.records.map((record) => {
      const n = record.get("n");

      return {
        id: n.elementId,
        type: n.labels[0],
        label:
          n.properties.name ||
          n.properties.title ||
          n.properties.value ||
          n.properties.id,
        properties: n.properties,
      };
    });
  } finally {
    await session.close();
  }
}
export async function getCampaigns() {
  const session = driver.session();

  try {
    const result = await session.run(`
      MATCH (c:Campaign)
      RETURN c
    `);

    return result.records.map((record) => {
      const c = record.get("c");

      return {
        id: c.elementId,
        name: c.properties.name,
      };
    });
  } finally {
    await session.close();
  }
}

export async function getCampaignByName(name: string) {
  const session = driver.session();

  try {
    const result = await session.run(
      `
      MATCH (c:Campaign {name: $name})-[:CONTAINS]->(a:Alert)
      RETURN c, collect(a) AS alerts
      `,
      { name }
    );

    if (result.records.length === 0) {
      return null;
    }

    const record = result.records[0];
    const campaign = record.get("c");
    const alerts = record.get("alerts");

    return {
      name: campaign.properties.name,
      alerts: alerts.map((a: any) => ({
        id: a.properties.id,
        title: a.properties.title,
        severity: a.properties.severity,
      })),
    };
  } finally {
    await session.close();
  }
}
export async function getAlerts() {
  const session = driver.session();

  try {
    const result = await session.run(`
      MATCH (a:Alert)
      RETURN a
    `);

    return result.records.map((record) => {
      const a = record.get("a");

      return {
        id: a.properties.id,
        title: a.properties.title,
        severity: a.properties.severity,
        sourceSystem: a.properties.sourceSystem,
      };
    });
  } finally {
    await session.close();
  }
}
export async function getLiveFeed() {
  const session = driver.session();

  try {
    const result = await session.run(`
      MATCH (a:Alert)
      RETURN a
      ORDER BY a.id DESC
      LIMIT 20
    `);

    return result.records.map((record) => {
      const a = record.get("a");

      return {
        id: a.properties.id,
        title: a.properties.title,
        severity: a.properties.severity,
        sourceSystem: a.properties.sourceSystem,
      };
    });
  } finally {
    await session.close();
  }
}

export async function executeCypherQuery(query: string) {
  const session = driver.session();
  try {
    const result = await session.run(query);
    const nodes: any[] = [];
    const edges: any[] = [];
    
    result.records.forEach((record) => {
      record.keys.forEach((key) => {
        const item = record.get(key);
        if (!item) return;

        // Determine if node or edge based on Neo4j driver types
        if (item.labels) {
          nodes.push({
            id: item.elementId || item.identity?.toString() || Math.random().toString(),
            label: item.properties.name || item.properties.title || item.properties.value || item.labels[0],
            type: item.labels[0],
            properties: item.properties
          });
        } else if (item.type) {
          edges.push({
            id: item.elementId || item.identity?.toString() || Math.random().toString(),
            source: item.startNodeElementId || item.start?.toString(),
            target: item.endNodeElementId || item.end?.toString(),
            label: item.type,
            properties: item.properties
          });
        }
      });
    });

    const uniqueNodes = Array.from(new Map(nodes.map(n => [n.id, n])).values());
    const uniqueEdges = Array.from(new Map(edges.map(e => [e.id, e])).values());

    return { nodes: uniqueNodes, edges: uniqueEdges };
  } finally {
    await session.close();
  }
}

export async function getEnrichedNeo4jCampaigns(): Promise<any[]> {
  const session = driver.session();
  try {
    const result = await session.run(`
      MATCH (c:Campaign)
      OPTIONAL MATCH (c)-[:CONTAINS]->(a:Alert)
      OPTIONAL MATCH (a)-[:USES]->(i)
      OPTIONAL MATCH (t:ThreatActor)-[:ATTRIBUTED_TO]->(c)
      OPTIONAL MATCH (c)-[:USES_TACTIC]->(m:MitreTactic)
      RETURN c, 
             collect(DISTINCT a) AS alerts, 
             collect(DISTINCT i) AS iocs, 
             collect(DISTINCT t) AS actors, 
             collect(DISTINCT m) AS tactics
    `);

    return result.records.map((record) => {
      const c = record.get("c");
      const alerts = record.get("alerts") || [];
      const iocs = record.get("iocs") || [];
      const actors = record.get("actors") || [];
      const tactics = record.get("tactics") || [];

      const props = c.properties || {};
      const name = props.name || "Unknown Campaign";

      const mappedAlerts = alerts.map((a: any) => ({
        id: a.properties.id,
        title: a.properties.title || "Unknown Alert",
        severity: a.properties.severity || "MEDIUM",
        sourceSystem: a.properties.sourceSystem || "SIEM",
        description: a.properties.description || "",
      }));

      // Parse recommended actions
      let recommendedActions: string[] = [];
      const actionsRaw = props.recommendedActions;
      if (Array.isArray(actionsRaw)) {
        recommendedActions = actionsRaw;
      } else if (typeof actionsRaw === "string") {
        try {
          const parsed = JSON.parse(actionsRaw);
          if (Array.isArray(parsed)) {
            recommendedActions = parsed;
          } else {
            recommendedActions = [actionsRaw];
          }
        } catch {
          recommendedActions = [actionsRaw];
        }
      } else {
        recommendedActions = [
          "Isolate all affected systems from the production network.",
          "Review IOCs against external threat intelligence feeds."
        ];
      }

      // Parse TTPs / Tactics
      const ttps = tactics.map((t: any) => t.properties.name || t.properties.id).filter(Boolean);

      return {
        id: c.elementId || c.identity?.toString() || `neo4j-${name}`,
        name,
        threatActor: actors[0]?.properties.name || props.threatActor || "Unknown Threat Actor",
        confidence: Number(props.confidence) || 85,
        riskScore: Number(props.riskScore) || (mappedAlerts.length > 0 ? Math.min(60 + mappedAlerts.length * 5, 95) : 75),
        status: props.status || "active",
        initialAccess: props.initialAccess || (mappedAlerts[0]?.title || "Under Analysis"),
        persistence: props.persistence || "Under Analysis",
        lateralMovement: props.lateralMovement || "Under Analysis",
        targetSector: props.targetSector || "Enterprise Infrastructure",
        summary: props.summary || props.description || `Threat campaign containing ${mappedAlerts.length} alerts.`,
        aiExplanation: props.aiExplanation || props.summary || `AI correlated threat campaign: ${name}.`,
        recommendedActions,
        alertsCount: mappedAlerts.length,
        iocsCount: iocs.length,
        ttps,
        relatedAlertIds: mappedAlerts.map((a: any) => a.id),
        createdAt: props.createdAt || new Date().toISOString(),
      };
    });
  } finally {
    await session.close();
  }
}