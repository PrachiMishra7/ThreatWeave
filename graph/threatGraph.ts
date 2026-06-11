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
    data.threatActor || null;
const alerts =
  data.extractedAlerts ||
  data.parsed_alerts ||
  data.security_incidents ||
  [];
  console.log("ALERT COUNT:", alerts.length);
  // Create Campaign Node
  await session.run(
      `
      MERGE (c:Campaign {name: $campaignName})
      `,
      { campaignName }
    );

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
           id: alert.id || alert.alert_id,
            title: alert.title || alert.event_type,
            severity: alert.severity || "MEDIUM",
            sourceSystem: alert.sourceSystem || "Groq",
          }
        );
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