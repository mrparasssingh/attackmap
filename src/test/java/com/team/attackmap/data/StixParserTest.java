package com.team.attackmap.data;

import com.team.attackmap.model.Technique;
import com.team.attackmap.util.Config;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Comprehensive test suite for StixParser verifying STIX 2.1 parsing,
 * filtering of revoked/deprecated techniques, sub-technique toggles,
 * exception handling, and duplicate detection.
 */
class StixParserTest {

    private static final Logger logger = LoggerFactory.getLogger(StixParserTest.class);
    private StixParser parser;

    @BeforeEach
    void setUp() {
        parser = new StixParser();
    }

    private InputStream getFixtureStream(String fixturePath) {
        InputStream is = getClass().getResourceAsStream(fixturePath);
        assertNotNull(is, "Fixture file not found on classpath: " + fixturePath);
        return is;
    }

    @Test
    @DisplayName("Parses valid active attack-pattern techniques correctly")
    void testParseValidAttackPatterns() {
        List<Technique> techniques = parser.parse(getFixtureStream("/fixtures/stix-sample.json"), true);

        assertNotNull(techniques);
        assertFalse(techniques.isEmpty());

        Technique t1059 = techniques.stream()
                .filter(t -> "T1059".equals(t.id()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("Technique T1059 not found"));

        assertEquals("Command and Scripting Interpreter", t1059.name());
        assertTrue(t1059.description().contains("command and script interpreters"));
        assertEquals(List.of("execution"), t1059.tactics());
        assertFalse(t1059.isSubTechnique());
    }

    @Test
    @DisplayName("Tactics are stored as lowercase kill-chain short names")
    void testTacticsAreLowercaseShortNames() {
        List<Technique> techniques = parser.parse(getFixtureStream("/fixtures/stix-sample.json"), true);

        Technique t1078 = techniques.stream()
                .filter(t -> "T1078".equals(t.id()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("Technique T1078 not found"));

        assertEquals("Valid Accounts", t1078.name());
        List<String> tactics = t1078.tactics();
        assertEquals(4, tactics.size());

        // Verify lowercase short names
        for (String tactic : tactics) {
            assertEquals(tactic.toLowerCase(Locale.ROOT), tactic,
                    "Tactic name must be strictly lowercase: " + tactic);
            assertFalse(tactic.contains(" "), "Tactic short name must not contain spaces: " + tactic);
        }

        assertTrue(tactics.contains("defense-evasion"));
        assertTrue(tactics.contains("initial-access"));
        assertTrue(tactics.contains("persistence"));
        assertTrue(tactics.contains("privilege-escalation"));
    }

    @Test
    @DisplayName("Excludes revoked techniques (revoked == true)")
    void testSkipRevokedTechniques() {
        List<Technique> techniques = parser.parse(getFixtureStream("/fixtures/stix-sample.json"), true);

        boolean containsRevoked = techniques.stream()
                .anyMatch(t -> "T1086".equals(t.id()));

        assertFalse(containsRevoked, "Revoked technique T1086 must be excluded");
    }

    @Test
    @DisplayName("Excludes deprecated techniques (x_mitre_deprecated == true)")
    void testSkipDeprecatedTechniques() {
        List<Technique> techniques = parser.parse(getFixtureStream("/fixtures/stix-sample.json"), true);

        boolean containsDeprecated = techniques.stream()
                .anyMatch(t -> "T1061".equals(t.id()));

        assertFalse(containsDeprecated, "Deprecated technique T1061 must be excluded");
    }

    @Test
    @DisplayName("Filtering revoked objects before duplicate detection permits revoked and active sharing ID")
    void testRevokedAndActiveObjectWithSameIdDoesNotThrow() {
        // Fixture contains both active T1059 and older revoked T1059.
        // Because revoked filtering occurs before duplicate detection, this must parse cleanly without error.
        assertDoesNotThrow(() -> {
            List<Technique> techniques = parser.parse(getFixtureStream("/fixtures/stix-sample.json"), true);
            long countT1059 = techniques.stream().filter(t -> "T1059".equals(t.id())).count();
            assertEquals(1, countT1059, "Exactly one active instance of T1059 should remain");
        });
    }

    @Test
    @DisplayName("Includes sub-techniques when includeSubTechniques flag is true")
    void testIncludeSubTechniques() {
        List<Technique> techniques = parser.parse(getFixtureStream("/fixtures/stix-sample.json"), true);

        Technique subTech = techniques.stream()
                .filter(t -> "T1059.001".equals(t.id()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("Sub-technique T1059.001 must be present"));

        assertTrue(subTech.isSubTechnique());
        assertEquals("PowerShell", subTech.name());
    }

    @Test
    @DisplayName("Excludes sub-techniques when includeSubTechniques flag is false")
    void testExcludeSubTechniques() {
        List<Technique> techniques = parser.parse(getFixtureStream("/fixtures/stix-sample.json"), false);

        boolean containsSubTech = techniques.stream()
                .anyMatch(t -> "T1059.001".equals(t.id()) || t.isSubTechnique());

        assertFalse(containsSubTech, "Sub-techniques must be excluded when flag is false");

        // Parent technique must still be present
        assertTrue(techniques.stream().anyMatch(t -> "T1059".equals(t.id())),
                "Parent technique T1059 must remain present");
    }

    @Test
    @DisplayName("Ignores non-attack-pattern objects such as malware and relationships")
    void testIgnoreNonAttackPatterns() {
        List<Technique> techniques = parser.parse(getFixtureStream("/fixtures/stix-sample.json"), true);

        for (Technique t : techniques) {
            assertNotEquals("Emotet", t.name(), "Malware objects must not be parsed as techniques");
        }
    }

    @Test
    @DisplayName("Handles missing optional fields safely with default values")
    void testMissingOptionalFields() {
        List<Technique> techniques = parser.parse(getFixtureStream("/fixtures/stix-sample.json"), true);

        Technique minimal = techniques.stream()
                .filter(t -> "T1999".equals(t.id()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("Minimal technique T1999 must be parsed"));

        assertEquals("Minimal Technique", minimal.name());
        assertNotNull(minimal.description(), "Description must not be null");
        assertEquals("", minimal.description(), "Missing description should default to empty string");
        assertNotNull(minimal.tactics(), "Tactics must not be null");
        assertTrue(minimal.tactics().isEmpty(), "Missing tactics should default to empty list");
        assertFalse(minimal.isSubTechnique(), "Missing subtechnique flag should default to false");
    }

    @Test
    @DisplayName("Correctly preserves non-ASCII UTF-8 characters")
    void testNonAsciiAndUnicodeEncoding() {
        List<Technique> techniques = parser.parse(getFixtureStream("/fixtures/stix-sample.json"), true);

        Technique unicodeTech = techniques.stream()
                .filter(t -> "T1888".equals(t.id()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("Unicode technique T1888 not found"));

        assertTrue(unicodeTech.name().contains("«Команда»"));
        assertTrue(unicodeTech.name().contains("“Smart Quotes”"));
        assertTrue(unicodeTech.description().contains("crème brûlée"));
        assertTrue(unicodeTech.description().contains("em—dash"));
    }

    @Test
    @DisplayName("Empty STIX bundle returns empty list without error")
    void testEmptyBundle() {
        String emptyBundle = """
                {
                  "type": "bundle",
                  "id": "bundle--empty",
                  "objects": []
                }
                """;

        List<Technique> techniques = parser.parse(emptyBundle, true);
        assertNotNull(techniques);
        assertTrue(techniques.isEmpty());
    }

    @Test
    @DisplayName("Malformed JSON input throws StixParseException")
    void testMalformedJsonThrowsStixParseException() {
        String invalidJson = "{ malformed json: not valid }";

        StixParseException thrown = assertThrows(StixParseException.class, () ->
                parser.parse(invalidJson, true));

        assertNotNull(thrown.getMessage());
    }

    @Test
    @DisplayName("Duplicate active technique IDs throw StixParseException in parse()")
    void testDuplicateActiveTechniqueIdThrowsInParse() {
        StixParseException thrown = assertThrows(StixParseException.class, () ->
                parser.parse(getFixtureStream("/fixtures/stix-duplicate-active.json"), true));

        assertTrue(thrown.getMessage().contains("T1059"),
                "Exception message should mention duplicate ID: " + thrown.getMessage());
    }

    @Test
    @DisplayName("Duplicate active technique IDs throw StixParseException in parseToMap()")
    void testDuplicateActiveTechniqueIdThrowsInParseToMap() {
        StixParseException thrown = assertThrows(StixParseException.class, () ->
                parser.parseToMap(getFixtureStream("/fixtures/stix-duplicate-active.json"), true));

        assertTrue(thrown.getMessage().contains("T1059"),
                "Exception message should mention duplicate ID: " + thrown.getMessage());
    }

    @Test
    @DisplayName("parseToMap returns immutable map indexed by technique ID")
    void testParseToMap() {
        Map<String, Technique> map = parser.parseToMap(getFixtureStream("/fixtures/stix-sample.json"), true);

        assertNotNull(map);
        assertTrue(map.containsKey("T1059"));
        assertTrue(map.containsKey("T1059.001"));
        assertTrue(map.containsKey("T1078"));
        assertFalse(map.containsKey("T1086")); // Revoked
        assertFalse(map.containsKey("T1061")); // Deprecated

        assertThrows(UnsupportedOperationException.class, () ->
                map.put("NEW", new Technique("NEW", "Name", "", List.of(), false)));
    }

    @Test
    @DisplayName("Extracts bundle version from x-mitre-collection")
    void testExtractBundleVersion() {
        String version = parser.extractBundleVersion(getFixtureStream("/fixtures/stix-sample.json"));
        assertEquals("20.0", version);
    }

    @Test
    @DisplayName("Real-data smoke test (conditional on -Dattack.stix.path)")
    @EnabledIfSystemProperty(named = "attack.stix.path", matches = ".+")
    void testRealDataSmokeTest() throws Exception {
        String filePath = System.getProperty("attack.stix.path");
        Path path = Paths.get(filePath);

        assertTrue(Files.exists(path), "Real ATT&CK STIX file must exist: " + path);

        // 1. Compute SHA-256 hash
        byte[] fileBytes = Files.readAllBytes(path);
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = digest.digest(fileBytes);
        String sha256 = HexFormat.of().formatHex(hashBytes);

        Instant lastModified = Files.getLastModifiedTime(path).toInstant();
        logger.info("Real ATT&CK Data Smoke Test: File={}, SHA-256={}, LastModified/Date={}",
                path.getFileName(), sha256, lastModified);

        // 2. Validate bundle version matches pinned Config.ATTACK_VERSION
        try (InputStream in = Files.newInputStream(path)) {
            String bundleVersion = parser.extractBundleVersion(in);
            assertEquals(Config.ATTACK_VERSION, bundleVersion,
                    "Bundle version must match Config.ATTACK_VERSION");
        }

        // 3. Range check: Parents only
        List<Technique> parentTechniques;
        try (InputStream in = Files.newInputStream(path)) {
            parentTechniques = parser.parse(in, false);
        }
        int parentCount = parentTechniques.size();
        logger.info("Parsed active parent techniques: count={}", parentCount);
        assertTrue(parentCount >= 180 && parentCount <= 400,
                "Parent technique count must be in range [180, 400], got: " + parentCount);

        // 4. Range check: With sub-techniques
        List<Technique> allTechniques;
        try (InputStream in = Files.newInputStream(path)) {
            allTechniques = parser.parse(in, true);
        }
        int totalCount = allTechniques.size();
        logger.info("Parsed active total techniques (including sub-techniques): count={}", totalCount);
        assertTrue(totalCount >= 550 && totalCount <= 1200,
                "Total technique count must be in range [550, 1200], got: " + totalCount);
        assertTrue(totalCount > parentCount, "Total count must exceed parent count");

        // 5. Check tactics: majority have non-empty lowercase tactics
        long techniquesWithValidTactics = allTechniques.stream()
                .filter(t -> !t.tactics().isEmpty() &&
                        t.tactics().stream().allMatch(tac -> tac.equals(tac.toLowerCase(Locale.ROOT)) && !tac.contains(" ")))
                .count();

        double ratio = (double) techniquesWithValidTactics / totalCount;
        logger.info("Ratio of techniques with non-empty lowercase tactics: {}/{} ({})",
                techniquesWithValidTactics, totalCount, String.format(Locale.ROOT, "%.2f%%", ratio * 100));

        assertTrue(ratio >= 0.95, "At least 95% of active techniques must declare lowercase tactics");
    }
}
