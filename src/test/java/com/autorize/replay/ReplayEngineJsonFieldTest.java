package com.autorize.replay;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class ReplayEngineJsonFieldTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void shouldReplaceRootAndNestedJsonFields() throws Exception {
        String json = """
                {
                  "userId": 1001,
                  "name": "Alice",
                  "active": true,
                  "account": {
                    "userId": 1001,
                    "plan": "free"
                  },
                  "roles": [
                    {"roleId": "admin", "userId": 1001}
                  ]
                }
                """;

        JsonNode root = objectMapper.readTree(json);
        boolean changed = replaceJsonFieldRecursive(root, "userId", "2002");
        assertThat(changed).isTrue();

        assertThat(root.get("userId").asLong()).isEqualTo(2002L);
        assertThat(root.get("account").get("userId").asLong()).isEqualTo(2002L);
        assertThat(root.get("roles").get(0).get("userId").asLong()).isEqualTo(2002L);
    }

    @Test
    void shouldReplaceDotPathField() throws Exception {
        String json = """
                {
                  "data": {
                    "tenant": {
                      "id": "tenant-alpha"
                    }
                  }
                }
                """;

        JsonNode root = objectMapper.readTree(json);
        boolean changed = replaceJsonFieldRecursive(root, "data.tenant.id", "tenant-beta");
        assertThat(changed).isTrue();
        assertThat(root.get("data").get("tenant").get("id").asText()).isEqualTo("tenant-beta");
    }

    private boolean replaceJsonFieldRecursive(JsonNode node, String targetKey, String replacementValue) {
        if (node == null) return false;
        boolean changed = false;

        if (targetKey.contains(".")) {
            String[] parts = targetKey.split("\\.", 2);
            String head = parts[0];
            String tail = parts[1];
            if (node.isObject() && node.has(head)) {
                return replaceJsonFieldRecursive(node.get(head), tail, replacementValue);
            }
            return false;
        }

        if (node.isObject()) {
            ObjectNode obj = (ObjectNode) node;
            List<String> toReplace = new ArrayList<>();
            var it = obj.fieldNames();
            while (it.hasNext()) {
                String field = it.next();
                if (field.equalsIgnoreCase(targetKey)) {
                    toReplace.add(field);
                }
            }
            for (String field : toReplace) {
                obj.set(field, parseReplacementJsonNode(replacementValue));
                changed = true;
            }

            var fieldsIt = obj.fields();
            while (fieldsIt.hasNext()) {
                var entry = fieldsIt.next();
                if (replaceJsonFieldRecursive(entry.getValue(), targetKey, replacementValue)) {
                    changed = true;
                }
            }
        } else if (node.isArray()) {
            ArrayNode arr = (ArrayNode) node;
            for (JsonNode item : arr) {
                if (replaceJsonFieldRecursive(item, targetKey, replacementValue)) {
                    changed = true;
                }
            }
        }
        return changed;
    }

    private JsonNode parseReplacementJsonNode(String val) {
        if (val == null || val.equalsIgnoreCase("null")) {
            return com.fasterxml.jackson.databind.node.NullNode.getInstance();
        }
        if (val.equalsIgnoreCase("true") || val.equalsIgnoreCase("false")) {
            return com.fasterxml.jackson.databind.node.BooleanNode.valueOf(Boolean.parseBoolean(val));
        }
        try {
            long l = Long.parseLong(val);
            return new com.fasterxml.jackson.databind.node.LongNode(l);
        } catch (NumberFormatException ignored) {}
        try {
            double d = Double.parseDouble(val);
            return new com.fasterxml.jackson.databind.node.DoubleNode(d);
        } catch (NumberFormatException ignored) {}
        if ((val.startsWith("{") && val.endsWith("}")) || (val.startsWith("[") && val.endsWith("]"))) {
            try {
                return objectMapper.readTree(val);
            } catch (Exception ignored) {}
        }
        return new com.fasterxml.jackson.databind.node.TextNode(val);
    }
}
