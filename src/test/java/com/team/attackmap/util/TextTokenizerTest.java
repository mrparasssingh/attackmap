package com.team.attackmap.util;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class TextTokenizerTest {

    private final TextTokenizer tokenizer = new TextTokenizer();

    @Test
    @DisplayName("Splits on punctuation and drops non-letters/digits")
    void splitsPunctuation() {
        List<String> tokens = tokenizer.tokenize("hello, world! foo-bar_baz... (test)");
        // "world" is not in our stopwords list, "hello", "foo", "bar", "baz", "test"
        assertTrue(tokens.contains("hello"));
        assertTrue(tokens.contains("world"));
        assertTrue(tokens.contains("foo"));
        assertTrue(tokens.contains("bar"));
        assertTrue(tokens.contains("baz"));
        assertTrue(tokens.contains("test"));
        for (String t : tokens) {
            assertTrue(t.matches("[\\p{L}\\p{N}]+"), "Token contains non-alphanumeric chars: " + t);
        }
    }

    @Test
    @DisplayName("Retains numeric digit tokens >= 2 characters")
    void retainsDigits() {
        List<String> tokens = tokenizer.tokenize("powershell 32 bit 64bit 1 23");
        assertTrue(tokens.contains("powershell"));
        assertTrue(tokens.contains("32"));
        assertTrue(tokens.contains("64bit"));
        assertTrue(tokens.contains("23"));
        assertFalse(tokens.contains("1"), "Single digit tokens must be dropped (< 2 chars)");
    }

    @Test
    @DisplayName("Drops tokens shorter than 2 characters")
    void dropsShortTokens() {
        List<String> tokens = tokenizer.tokenize("a b c d 1 2 ok go run");
        assertFalse(tokens.contains("a"));
        assertFalse(tokens.contains("b"));
        assertFalse(tokens.contains("1"));
        assertTrue(tokens.contains("ok"));
        assertTrue(tokens.contains("go"));
        assertTrue(tokens.contains("run"));
    }

    @Test
    @DisplayName("Filters out stopwords from stopwords.txt")
    void filtersStopwords() {
        List<String> tokens = tokenizer.tokenize("the adversary had an apple and they were under the table");
        assertFalse(tokens.contains("the"));
        assertFalse(tokens.contains("had"));
        assertFalse(tokens.contains("an"));
        assertFalse(tokens.contains("and"));
        assertFalse(tokens.contains("they"));
        assertFalse(tokens.contains("were"));
        assertFalse(tokens.contains("under"));
        assertTrue(tokens.contains("adversary"));
        assertTrue(tokens.contains("apple"));
        assertTrue(tokens.contains("table"));
    }

    @Test
    @DisplayName("Preserves security-relevant words like run, execute, remote, file, access, use")
    void preservesSecurityWords() {
        List<String> tokens = tokenizer.tokenize("adversaries run and execute remote access tools to use file");
        assertTrue(tokens.contains("run"));
        assertTrue(tokens.contains("execute"));
        assertTrue(tokens.contains("remote"));
        assertTrue(tokens.contains("access"));
        assertTrue(tokens.contains("use"));
        assertTrue(tokens.contains("file"));
    }

    @Test
    @DisplayName("Handles non-ASCII Unicode characters (curly quotes, em-dash, Cyrillic) without crashing")
    void handlesNonAscii() {
        List<String> tokens = tokenizer.tokenize("“Adversary”—атака ‘malware’");
        // “ and ” are non-alphanumeric punctuation, — is em-dash
        // атака is Cyrillic letters (valid Unicode letters)
        assertTrue(tokens.contains("adversary"));
        assertTrue(tokens.contains("malware"));
        assertTrue(tokens.contains("атака"));
    }

    @Test
    @DisplayName("TokenizeToSet returns a deduplicated set of tokens")
    void tokenizeToSetDeduplicates() {
        Set<String> tokenSet = tokenizer.tokenizeToSet("execute execute EXECUTE remote remote");
        assertEquals(Set.of("execute", "remote"), tokenSet);
    }

    @Test
    @DisplayName("Throws descriptive IllegalStateException or IOException when stopwords resource is missing")
    void missingStopwordsThrows() {
        assertThrows(IllegalStateException.class, () -> {
            TextTokenizer.loadStopwords("nonexistent-stopwords-file-xyz.txt");
        });
    }

    @Test
    @DisplayName("Handles comments (#) and blank lines in custom stopwords stream")
    void handlesCommentsAndBlankLines() throws IOException {
        String data = "# This is a comment\n\nwordone\n# another comment\nwordtwo\n";
        try (InputStream in = new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8))) {
            Set<String> loaded = TextTokenizer.loadStopwordsFromStream(in);
            assertEquals(Set.of("wordone", "wordtwo"), loaded);
        }
    }
}

