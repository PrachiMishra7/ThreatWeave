import driver from "./neo4j";

export async function saveThreatGraph(data: any) {
  const session = driver.session();

  try {
    const campaignName =
      data.campaignProposedName || "Unknown Campaign";

    // Create Campaign Node
    await session.run(
      `
      MERGE (c:Campaign {name: $campaignName})
      `,
      { campaignName }
    );

    // Create Alert Nodes
    if (data.extractedAlerts) {
      for (const alert of data.extractedAlerts) {
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
            id: alert.id,
            title: alert.title,
            severity: alert.severity,
            sourceSystem: alert.sourceSystem,
          }
        );

        // Create IOC Nodes
        if (alert.iocs) {
          for (const ioc of alert.iocs) {
            await session.run(
              `
              MATCH (a:Alert {id: $alertId})

              MERGE (i:IOC {
                type: $type,
                value: $value
              })

              MERGE (a)-[:USES]->(i)
              `,
              {
                alertId: alert.id,
                type: ioc.type,
                value: ioc.value,
              }
            );
          }
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