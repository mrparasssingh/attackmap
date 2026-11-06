package com.team.attackmap.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Utility for normalizing threat report text and splitting it into discrete sentences.
 * <p>
 * Normalization performs the following steps:
 * <ul>
 *   <li>Drops lines that consist solely of a page number or match the pattern "Page N [of M]".</li>
 *   <li>Joins hyphenated word-breaks across lines ("word-\nrest") when the continuation line begins
 *       with a lowercase letter. <i>Limitation:</i> Hyphenated terms followed by an uppercase letter
 *       or proper noun (e.g. "anti-\nRussian") are intentionally not merged.</li>
 *   <li>Joins hard-wrapped lines within paragraphs and collapses redundant whitespace into a single space.</li>
 *   <li>Treats bullet lines (e.g. starting with '-', '*', or '•') and numbered list items (e.g. "1.", "2)")
 *       as distinct sentence boundaries so each list entry is extracted as its own sentence.</li>
 * </ul>
 * <p>
 * Sentences are split after terminal punctuation ('.', '!', '?') followed by whitespace and an uppercase
 * letter, digit, quotation mark, or bracket.
 * <p>
 * Splits are suppressed inside technical entities such as MITRE ATT&amp;CK technique IDs (e.g. T1059.001),
 * filenames (e.g. malware.exe), domain names (e.g. evil.example.com), defanged indicators (e.g.
 * evil[.]example[.]com, hxxp://evil[.]com/a), IP addresses (e.g. 192.168.1.10), software versions (e.g. v2.1.3),
 * decimal numbers (e.g. 3.5), URLs, Windows file paths, and common abbreviations loaded from
 * {@code abbreviations.txt} (e.g. e.g., i.e., U.S., Dr., vs., etc., Fig., No.).
 * <p>
 * <i>Limitation:</i> A sentence ending with an abbreviation followed by a period and a capitalized word
 * (such as "..., etc. The attacker...") is not split across that boundary, because abbreviations
 * suppress sentence delimiters to prevent mid-sentence fragmentation.
 */
public final class SentenceSplitter {

    private static final String DEFAULT_ABBREVIATIONS_RESOURCE = "abbreviations.txt";

    private static final Pattern PAGE_LINE_PATTERN =
            Pattern.compile("(?i)^[ \\t]*(?:page[ \\t]+\\d+(?:[ \\t]+of[ \\t]+\\d+)?|\\d+)[ \\t]*$");

    private static final Pattern HYPHEN_WORD_BREAK =
            Pattern.compile("(\\b\\p{L}+)-\\n[ \\t]*(\\p{Ll})");

    private static final Pattern LIST_PREFIX_PATTERN =
            Pattern.compile("^(?:[-*•]|\\d+[.)])[ \\t]+");

    private static final Pattern MULTI_WHITESPACE =
            Pattern.compile("[ \\t]+");

    private static final Pattern NUMBERED_PREFIX_ONLY =
            Pattern.compile("^\\d+$");

    private static final Set<String> DIGIT_REQUIRING_ABBREVIATIONS =
            Set.of("no.", "fig.", "st.");

    private static final Set<String> ABBREVIATIONS = loadAbbreviations(DEFAULT_ABBREVIATIONS_RESOURCE);

    private SentenceSplitter() {
        // Prevent instantiation of utility class
    }

    /**
     * Normalizes raw report text and splits it into discrete sentences.
     *
     * @param text Raw report text to normalize and split.
     * @return An unmodifiable List of normalized sentences. Returns an empty list if input is null or blank.
     */
    public static List<String> split(String text) {
        if (text == null || text.isBlank()) {
            return Collections.emptyList();
        }

        List<String> normalizedBlocks = normalizeToBlocks(text);
        List<String> sentences = new ArrayList<>();

        for (String block : normalizedBlocks) {
            splitBlockIntoSentences(block, sentences);
        }

        return Collections.unmodifiableList(sentences);
    }

    /**
     * Normalizes raw text into individual paragraphs or list-item blocks.
     *
     * @param rawText Raw text string.
     * @return Ordered list of normalized paragraph or list blocks.
     */
    private static List<String> normalizeToBlocks(String rawText) {
        String standardized = rawText.replace("\r\n", "\n").replace('\r', '\n');
        String[] rawLines = standardized.split("\n", -1);

        // 1. Drop page number lines and Page N [of M] lines
        StringBuilder pageFiltered = new StringBuilder();
        for (String line : rawLines) {
            if (!PAGE_LINE_PATTERN.matcher(line).matches()) {
                if (pageFiltered.length() > Config.ZERO) {
                    pageFiltered.append('\n');
                }
                pageFiltered.append(line);
            }
        }

        // 2. Join hyphenated line breaks when next line starts lowercase
        String dehyphenated = HYPHEN_WORD_BREAK.matcher(pageFiltered.toString()).replaceAll("$1$2");
        String[] contentLines = dehyphenated.split("\n", -1);

        // 3. Assemble blocks: separate on list prefixes or empty lines, merge wrapped lines
        List<String> blocks = new ArrayList<>();
        StringBuilder currentBlock = new StringBuilder();

        for (String line : contentLines) {
            String trimmed = line.trim();
            if (trimmed.isEmpty()) {
                if (currentBlock.length() > Config.ZERO) {
                    blocks.add(collapseWhitespace(currentBlock.toString()));
                    currentBlock.setLength(Config.ZERO);
                }
                continue;
            }

            boolean isListLine = LIST_PREFIX_PATTERN.matcher(trimmed).find();
            if (isListLine) {
                if (currentBlock.length() > Config.ZERO) {
                    blocks.add(collapseWhitespace(currentBlock.toString()));
                    currentBlock.setLength(Config.ZERO);
                }
                currentBlock.append(trimmed);
            } else {
                if (currentBlock.length() > Config.ZERO) {
                    currentBlock.append(' ').append(trimmed);
                } else {
                    currentBlock.append(trimmed);
                }
            }
        }

        if (currentBlock.length() > Config.ZERO) {
            blocks.add(collapseWhitespace(currentBlock.toString()));
        }

        return blocks;
    }

    /**
     * Splits an individual text block into discrete sentences using terminal punctuation rules.
     *
     * @param block     Normalized text block.
     * @param sentences Output accumulator for extracted sentences.
     */
    private static void splitBlockIntoSentences(String block, List<String> sentences) {
        int sentenceStart = Config.ZERO;
        int len = block.length();
        int i = Config.ZERO;

        while (i < len) {
            char c = block.charAt(i);
            if (c == '.' || c == '!' || c == '?') {
                int punctEnd = i;
                if (punctEnd + Config.ONE < len) {
                    char nextC = block.charAt(punctEnd + Config.ONE);
                    if (isClosingQuoteOrBracket(nextC)) {
                        punctEnd++;
                    }
                }

                int ws = punctEnd + Config.ONE;
                while (ws < len && Character.isWhitespace(block.charAt(ws))) {
                    ws++;
                }

                if (ws > punctEnd + Config.ONE && ws < len && isSentenceStartChar(block.charAt(ws))) {
                    char nextChar = block.charAt(ws);
                    if (c == '.' && isAbbreviation(block, i, nextChar)) {
                        i = ws;
                        continue;
                    }

                    if (c == '.' && isNumberedListPrefix(block, sentenceStart, i)) {
                        i = ws;
                        continue;
                    }

                    String sentence = block.substring(sentenceStart, punctEnd + Config.ONE).trim();
                    if (!sentence.isEmpty()) {
                        sentences.add(sentence);
                    }
                    sentenceStart = ws;
                    i = ws;
                    continue;
                }
            }
            i++;
        }

        if (sentenceStart < len) {
            String remaining = block.substring(sentenceStart).trim();
            if (!remaining.isEmpty()) {
                sentences.add(remaining);
            }
        }
    }

    /**
     * Determines whether the period at {@code periodIndex} is preceded by a recognized abbreviation.
     * Abbreviations that are short English words (such as "no.", "fig.", "st.") suppress a split
     * only when followed by a digit.
     */
    private static boolean isAbbreviation(String text, int periodIndex, char nextChar) {
        int start = periodIndex - Config.ONE;
        while (start >= Config.ZERO) {
            char c = text.charAt(start);
            if (Character.isLetter(c) || c == '.') {
                start--;
            } else {
                break;
            }
        }
        String candidate = text.substring(start + Config.ONE, periodIndex + Config.ONE).toLowerCase(Locale.ROOT);
        if (DIGIT_REQUIRING_ABBREVIATIONS.contains(candidate)) {
            return Character.isDigit(nextChar);
        }
        return ABBREVIATIONS.contains(candidate);
    }

    /**
     * Determines whether the period at {@code periodIndex} forms a numbered list prefix (e.g. "1.")
     * at the start of the current sentence fragment.
     */
    private static boolean isNumberedListPrefix(String text, int sentenceStart, int periodIndex) {
        String prefixCandidate = text.substring(sentenceStart, periodIndex).trim();
        return NUMBERED_PREFIX_ONLY.matcher(prefixCandidate).matches();
    }

    /**
     * Determines if the character represents a valid sentence-starting character after whitespace.
     */
    private static boolean isSentenceStartChar(char c) {
        return Character.isUpperCase(c)
                || Character.isDigit(c)
                || Character.getType(c) == Character.TITLECASE_LETTER
                || isOpeningQuoteOrBracket(c);
    }

    /**
     * Determines if the character is an opening quote or bracket.
     */
    private static boolean isOpeningQuoteOrBracket(char c) {
        return c == '"' || c == '\'' || c == '“' || c == '‘' || c == '«'
                || c == '(' || c == '[' || c == '{';
    }

    /**
     * Determines if the character is a closing quote or bracket attached to terminal punctuation.
     */
    private static boolean isClosingQuoteOrBracket(char c) {
        return c == '"' || c == '\'' || c == '”' || c == '’' || c == '»'
                || c == ')' || c == ']' || c == '}';
    }

    /**
     * Collapses multiple consecutive horizontal whitespace characters into a single space.
     */
    private static String collapseWhitespace(String text) {
        return MULTI_WHITESPACE.matcher(text.trim()).replaceAll(" ");
    }

    /**
     * Loads abbreviations from classpath resource in UTF-8.
     *
     * @param resourcePath Classpath location of abbreviations file.
     * @return Set of lowercase abbreviations with guaranteed trailing period.
     */
    private static Set<String> loadAbbreviations(String resourcePath) {
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        if (classLoader == null) {
            classLoader = SentenceSplitter.class.getClassLoader();
        }

        try (InputStream in = classLoader.getResourceAsStream(resourcePath)) {
            if (in == null) {
                throw new IllegalStateException("Abbreviations resource not found on classpath: " + resourcePath);
            }
            Set<String> set = new HashSet<>();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    String trimmed = line.trim();
                    if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                        continue;
                    }
                    String lower = trimmed.toLowerCase(Locale.ROOT);
                    set.add(lower.endsWith(".") ? lower : lower + ".");
                }
            }
            return Collections.unmodifiableSet(set);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to read abbreviations resource: " + resourcePath, e);
        }
    }
}
