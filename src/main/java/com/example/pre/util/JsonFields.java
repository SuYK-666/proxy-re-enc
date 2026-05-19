package com.example.pre.util;

import java.util.LinkedHashMap;
import java.util.Map;

public final class JsonFields {
    private JsonFields() {
    }

    public static Map<String, String> parseObject(String body) {
        String trimmedBody = body == null ? "" : body.trim();
        if (!trimmedBody.startsWith("{") || !trimmedBody.endsWith("}")) {
            throw new IllegalArgumentException("JSON object must start with { and end with }");
        }
        Map<String, String> out = new LinkedHashMap<>();
        String trimmed = trimmedBody.substring(1, trimmedBody.length() - 1).trim();
        if (trimmed.isEmpty()) {
            return out;
        }
        for (String item : splitTopLevel(trimmed)) {
            int idx = topLevelColon(item);
            if (idx <= 0) {
                throw new IllegalArgumentException("invalid JSON object field: " + item);
            }
            String key = parseString(item.substring(0, idx).trim());
            String value = parseValue(item.substring(idx + 1).trim());
            out.put(key, value);
        }
        return out;
    }

    private static java.util.List<String> splitTopLevel(String input) {
        java.util.List<String> items = new java.util.ArrayList<>();
        StringBuilder current = new StringBuilder();
        boolean inString = false;
        boolean escaped = false;
        int depth = 0;
        for (int i = 0; i < input.length(); i++) {
            char ch = input.charAt(i);
            if (escaped) {
                current.append(ch);
                escaped = false;
                continue;
            }
            if (ch == '\\' && inString) {
                current.append(ch);
                escaped = true;
                continue;
            }
            if (ch == '"') {
                inString = !inString;
            } else if (!inString && (ch == '{' || ch == '[')) {
                depth++;
            } else if (!inString && (ch == '}' || ch == ']')) {
                depth--;
                if (depth < 0) {
                    throw new IllegalArgumentException("unbalanced JSON brackets");
                }
            } else if (!inString && depth == 0 && ch == ',') {
                items.add(current.toString());
                current.setLength(0);
                continue;
            }
            current.append(ch);
        }
        if (inString || depth != 0) {
            throw new IllegalArgumentException("unterminated JSON object");
        }
        if (!current.isEmpty()) {
            items.add(current.toString());
        }
        return items;
    }

    private static int topLevelColon(String input) {
        boolean inString = false;
        boolean escaped = false;
        int depth = 0;
        for (int i = 0; i < input.length(); i++) {
            char ch = input.charAt(i);
            if (escaped) {
                escaped = false;
                continue;
            }
            if (ch == '\\' && inString) {
                escaped = true;
                continue;
            }
            if (ch == '"') {
                inString = !inString;
            } else if (!inString && (ch == '{' || ch == '[')) {
                depth++;
            } else if (!inString && (ch == '}' || ch == ']')) {
                depth--;
            } else if (!inString && depth == 0 && ch == ':') {
                return i;
            }
        }
        return -1;
    }

    private static String parseValue(String value) {
        String trimmed = value.trim();
        if (trimmed.startsWith("\"")) {
            return parseString(trimmed);
        }
        if ("null".equals(trimmed)) {
            return "";
        }
        return trimmed;
    }

    private static String parseString(String value) {
        String trimmed = value.trim();
        if (!trimmed.startsWith("\"") || !trimmed.endsWith("\"") || trimmed.length() < 2) {
            throw new IllegalArgumentException("JSON object keys and string values must be quoted");
        }
        String raw = trimmed.substring(1, trimmed.length() - 1);
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < raw.length(); i++) {
            char ch = raw.charAt(i);
            if (ch != '\\') {
                out.append(ch);
                continue;
            }
            if (++i >= raw.length()) {
                throw new IllegalArgumentException("invalid JSON escape");
            }
            char escaped = raw.charAt(i);
            switch (escaped) {
                case '"' -> out.append('"');
                case '\\' -> out.append('\\');
                case '/' -> out.append('/');
                case 'b' -> out.append('\b');
                case 'f' -> out.append('\f');
                case 'n' -> out.append('\n');
                case 'r' -> out.append('\r');
                case 't' -> out.append('\t');
                case 'u' -> {
                    if (i + 4 >= raw.length()) {
                        throw new IllegalArgumentException("invalid unicode escape");
                    }
                    String hex = raw.substring(i + 1, i + 5);
                    out.append((char) Integer.parseInt(hex, 16));
                    i += 4;
                }
                default -> throw new IllegalArgumentException("unsupported JSON escape: \\" + escaped);
            }
        }
        return out.toString();
    }
}
