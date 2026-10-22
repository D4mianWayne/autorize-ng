package com.autorize.export;

import com.autorize.model.EnforcementStatus;
import com.autorize.model.LogEntry;
import com.autorize.persistence.PersistenceManager;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.File;
import java.io.IOException;
import java.util.List;

public class SarifExporter {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    public static void exportToSarif(File targetFile, PersistenceManager persistenceManager) throws IOException {
        ObjectNode root = MAPPER.createObjectNode();
        root.put("$schema", "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json");
        root.put("version", "2.1.0");

        ArrayNode runs = root.putArray("runs");
        ObjectNode run = MAPPER.createObjectNode();

        // Tool Component
        ObjectNode tool = run.putObject("tool");
        ObjectNode driver = tool.putObject("driver");
        driver.put("name", "Autorize Next-Gen");
        driver.put("semanticVersion", "2.0.0");
        driver.put("informationUri", "https://github.com/Quitten/Autorize");

        ArrayNode rules = driver.putArray("rules");
        ObjectNode ruleBOLA = rules.addObject();
        ruleBOLA.put("id", "AUTORIZE-001");
        ruleBOLA.put("name", "BrokenObjectLevelAuthorization");
        ruleBOLA.putObject("shortDescription").put("text", "Broken Object Level Authorization (IDOR) Detected");

        ObjectNode ruleAuth = rules.addObject();
        ruleAuth.put("id", "AUTORIZE-002");
        ruleAuth.put("name", "MissingAuthentication");
        ruleAuth.putObject("shortDescription").put("text", "Missing Authentication Check on Protected Resource");

        ArrayNode results = run.putArray("results");
        List<LogEntry> logs = persistenceManager.getLogEntries();

        for (LogEntry log : logs) {
            // Check unauth bypass
            if (log.getUnauthStatus() == EnforcementStatus.BYPASSED) {
                ObjectNode res = results.addObject();
                res.put("ruleId", "AUTORIZE-002");
                res.put("level", "error");
                res.putObject("message").put("text", String.format("Endpoint %s %s accessible without authentication.", log.getMethod(), log.getUrl()));

                ArrayNode locations = res.putArray("locations");
                ObjectNode loc = locations.addObject();
                loc.putObject("physicalLocation").putObject("artifactLocation").put("uri", log.getUrl());
            }

            // Check per-user bypasses
            log.getUserResults().forEach((userId, userResult) -> {
                if (userResult.getStatus() == EnforcementStatus.BYPASSED) {
                    ObjectNode res = results.addObject();
                    res.put("ruleId", "AUTORIZE-001");
                    res.put("level", "error");
                    res.putObject("message").put("text", String.format("Authorization bypass detected for user %s on %s %s: %s",
                            userId, log.getMethod(), log.getUrl(), userResult.getDiffDetails()));

                    ArrayNode locations = res.putArray("locations");
                    ObjectNode loc = locations.addObject();
                    loc.putObject("physicalLocation").putObject("artifactLocation").put("uri", log.getUrl());
                }
            });
        }

        runs.add(run);
        MAPPER.writerWithDefaultPrettyPrinter().writeValue(targetFile, root);
    }
}
