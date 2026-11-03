package com.team.attackmap.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Text tokenization utility for keyword extraction and matching.
 * Performs Unicode-aware lowercase normalization, token splitting on non-alphanumeric characters,
 * short-token pruning (&lt; 2 characters), and stopword removal.
 */
public final class TextTokenizer {

    private static final String DEFAULT_STOPWORDS_RESOURCE = "stopwords.txt";
    private static final Pattern NON_ALPHANUMERIC = Pattern.compile("[^\\p{L}\\p{N}]+");

    private final Set<String> stopwords;

    /**
     * Constructs a TextTokenizer loading stopwords from the default classpath resource "stopwords.txt".
     *
     * @throws IllegalStateException If the stopwords resource cannot be found or read.
     */
    public TextTokenizer() {
        this(loadStopwords(DEFAULT_STOPWORDS_RESOURCE));
    }

    /**
     * Constructs a TextTokenizer with an explicit set of stopwords.
     *
     * @param stopwords Set of stopwords to filter out (defensively copied).
     */
    public TextTokenizer(Set<String> stopwords) {
        Objects.requireNonNull(stopwords, "stopwords set cannot be null");
        this.stopwords = Set.copyOf(stopwords);
    }

    /**
     * Tokenizes an input text string into an ordered list of valid tokens.
     *
     * @param text The input text string to tokenize.
     * @return An unmodifiable List of extracted tokens. Returns an empty list if input is null or blank.
     */
    public List<String> tokenize(String text) {
        if (text == null || text.isBlank()) {
            return Collections.emptyList();
        }

        String normalized = text.toLowerCase(Locale.ROOT);
        String[] rawTokens = NON_ALPHANUMERIC.split(normalized);

        List<String> validTokens = new ArrayList<>(rawTokens.length);
        for (String raw : rawTokens) {
            if (raw.length() >= 2 && !stopwords.contains(raw)) {
                validTokens.add(raw);
            }
        }

        return Collections.unmodifiableList(validTokens);
    }

    /**
     * Tokenizes an input text string into a deduplicated Set of unique tokens.
     *
     * @param text The input text string to tokenize.
     * @return An unmodifiable Set of unique extracted tokens. Returns an empty set if input is null or blank.
     */
    public Set<String> tokenizeToSet(String text) {
        List<String> tokenList = tokenize(text);
        if (tokenList.isEmpty()) {
            return Collections.emptySet();
        }
        return Collections.unmodifiableSet(new HashSet<>(tokenList));
    }

    /**
     * Loads a set of stopwords from a classpath resource.
     * Lines starting with '#' are treated as comments, and blank lines are ignored.
     *
     * @param resourcePath Classpath location of the stopwords file.
     * @return An unmodifiable Set of lowercase stopwords.
     * @throws IllegalStateException If the resource cannot be found or an I/O error occurs.
     */
    public static Set<String> loadStopwords(String resourcePath) {
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        if (classLoader == null) {
            classLoader = TextTokenizer.class.getClassLoader();
        }

        try (InputStream in = classLoader.getResourceAsStream(resourcePath)) {
            if (in == null) {
                throw new IllegalStateException("Stopwords resource not found on classpath: " + resourcePath);
            }
            return loadStopwordsFromStream(in);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to read stopwords resource: " + resourcePath, e);
        }
    }

    /**
     * Reads stopwords from an input stream in UTF-8.
     * Lines starting with '#' are treated as comments, and blank lines are ignored.
     *
     * @param in Input stream supplying the stopwords text.
     * @return An unmodifiable Set of lowercase stopwords.
     * @throws IOException If reading fails.
     */
    public static Set<String> loadStopwordsFromStream(InputStream in) throws IOException {
        Objects.requireNonNull(in, "InputStream cannot be null");
        Set<String> words = new HashSet<>();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String trimmed = line.trim();
                if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                    continue;
                }
                words.add(trimmed.toLowerCase(Locale.ROOT));
            }
        }
        return Collections.unmodifiableSet(words);
    }
}

