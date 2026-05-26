package com.example.pre.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class JsonFieldsTest {
    @Test
    void parsesEscapedStringsAndNestedRawValues() {
        var fields = JsonFields.parseObject("{"
                + "\"fileName\":\"a:b, c.txt\","
                + "\"purpose\":\"line\\nwith unicode \\u4e2d\\u6587\","
                + "\"policy\":{\"allowDownload\":true},"
                + "\"tags\":[\"a,b\",\"c:d\"]"
                + "}");

        assertEquals("a:b, c.txt", fields.get("fileName"));
        assertEquals("line\nwith unicode 中文", fields.get("purpose"));
        assertEquals("{\"allowDownload\":true}", fields.get("policy"));
        assertEquals("[\"a,b\",\"c:d\"]", fields.get("tags"));
    }

    @Test
    void rejectsMalformedJsonObjects() {
        assertThrows(IllegalArgumentException.class, () -> JsonFields.parseObject("{\"a\":\"unterminated}"));
        assertThrows(IllegalArgumentException.class, () -> JsonFields.parseObject("{a:\"missing quoted key\"}"));
    }
}
