// =============================================================================
// TrustShare — MongoDB Collection Initialization & Indexes
// Automatically executed by mongo:7 container on first startup, or manually via:
//   mongosh mongodb://localhost:27017/trustshare backend/scripts/init_mongo.js
// =============================================================================

const tsDb = db.getSiblingDB("trustshare");

// 1. Immutable Audit & File Activity Logs
if (!tsDb.getCollectionNames().includes("audit_logs")) {
  tsDb.createCollection("audit_logs", {
    validator: {
      $jsonSchema: {
        bsonType: "object",
        required: ["event_id", "timestamp", "action", "category", "status", "severity"],
        properties: {
          event_id: { bsonType: "string" },
          timestamp: { bsonType: "string" },
          actor_id: { bsonType: ["string", "null"] },
          actor_email: { bsonType: ["string", "null"] },
          actor_role: { bsonType: ["string", "null"] },
          action: { bsonType: "string" },
          category: { enum: ["auth", "file", "folder", "share", "security", "admin", "system"] },
          resource_type: { bsonType: ["string", "null"] },
          resource_id: { bsonType: ["string", "null"] },
          resource_name: { bsonType: ["string", "null"] },
          status: { enum: ["success", "failure", "blocked"] },
          severity: { enum: ["info", "warning", "critical"] },
          ip_address: { bsonType: ["string", "null"] },
          user_agent: { bsonType: ["string", "null"] },
          request_id: { bsonType: ["string", "null"] },
          details: { bsonType: "object" }
        }
      }
    },
    validationLevel: "moderate"
  });
}

tsDb.audit_logs.createIndex({ event_id: 1 }, { unique: true });
tsDb.audit_logs.createIndex({ timestamp: -1 });
tsDb.audit_logs.createIndex({ actor_id: 1, timestamp: -1 });
tsDb.audit_logs.createIndex({ resource_type: 1, resource_id: 1, timestamp: -1 });
tsDb.audit_logs.createIndex({ category: 1, severity: 1, timestamp: -1 });
tsDb.audit_logs.createIndex({ action: 1, status: 1, timestamp: -1 });

// 2. Security Events (Failed login bursts, rejected uploads, unauthorized RBAC probes)
if (!tsDb.getCollectionNames().includes("security_events")) {
  tsDb.createCollection("security_events");
}
tsDb.security_events.createIndex({ timestamp: -1 });
tsDb.security_events.createIndex({ severity: 1, resolved: 1, timestamp: -1 });
tsDb.security_events.createIndex({ ip_address: 1, timestamp: -1 });

print("TrustShare MongoDB collections and indexes initialized.");
