package com.team.attackmap.data;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.team.attackmap.model.Technique;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

/**
 * High-performance parser for MITRE ATT&CK STIX 2.1 JSON bundles.
 * Extracts active attack-pattern techniques into immutable {@link Technique} instances,
 * excludes revoked and deprecated items, enforces sub-technique inclusion/exclusion,
 * and detects data integrity violations such as duplicate active technique IDs.
 */
public class StixParser {

    private static final Logger logger = LoggerFactory.getLogger(StixParser.class);
    private static final String TYPE_ATTACK_PATTERN = "attack-pattern";
    private static final String TYPE_COLLECTION = "x-mitre-collection";
    private static final String MITRE_ATTACK_SOURCE = "mitre-attack";

    private final ObjectMapper mapper;

    /**
     * Constructs a new StixParser with a default Jackson ObjectMapper.
     */
    public StixParser() {
        this.mapper = new ObjectMapper();
    }

    /**
     * Parses a STIX JSON input stream into a list of Techniques.
     * Revoked and deprecated objects are filtered out before duplicate ID detection.
     *
     * @param in                   The input stream containing STIX 2.1 JSON.
     * @param includeSubTechniques Whether to include sub-techniques (true) or parent techniques only (false).
     * @return An unmodifiable List of parsed active Technique objects.
     * @throws StixParseException If JSON syntax is invalid, stream fails to read, or duplicate active technique IDs exist.
     */
    public List<Technique> parse(InputStream in, boolean includeSubTechniques) {
        if (in == null) {
            throw new StixParseException("STIX InputStream cannot be null");
        }

        JsonNode rootNode;
        try {
            rootNode = mapper.readTree(in);
        } catch (JsonProcessingException e) {
            throw new StixParseException("Malformed STIX JSON syntax: " + e.getMessage(), e);
        } catch (IOException e) {
            throw new StixParseException("IO failure while reading STIX JSON input: " + e.getMessage(), e);
        }

        if (rootNode == null || rootNode.isNull()) {
            throw new StixParseException("STIX JSON content is empty or null");
        }

        JsonNode objectsNode = rootNode.get("objects");
        if (objectsNode == null || !objectsNode.isArray()) {
            throw new StixParseException("Invalid STIX bundle: missing 'objects' array");
        }

        List<Technique> techniques = new ArrayList<>();
        Set<String> activeIds = new HashSet<>();

        for (JsonNode obj : objectsNode) {
            // 1. Only process attack-pattern objects
            JsonNode typeNode = obj.get("type");
            if (typeNode == null || !TYPE_ATTACK_PATTERN.equals(typeNode.asText())) {
                continue;
            }

            // 2. Revoked filter (applied before duplicate detection)
            JsonNode revokedNode = obj.get("revoked");
            if (revokedNode != null && revokedNode.asBoolean(false)) {
                continue;
            }

            // 3. Deprecated filter (applied before duplicate detection)
            JsonNode deprecatedNode = obj.get("x_mitre_deprecated");
            if (deprecatedNode != null && deprecatedNode.asBoolean(false)) {
                continue;
            }

            // 4. Extract external MITRE technique ID
            String techniqueId = extractTechniqueId(obj);
            if (techniqueId == null || techniqueId.isBlank()) {
                continue;
            }

            // 5. Sub-technique filter
            boolean isSubTechnique = obj.path("x_mitre_is_subtechnique").asBoolean(false);
            if (!includeSubTechniques && isSubTechnique) {
                continue;
            }

            // 6. Duplicate active technique ID detection
            if (activeIds.contains(techniqueId)) {
                throw new StixParseException("Duplicate active technique ID encountered: " + techniqueId);
            }
            activeIds.add(techniqueId);

            // 7. Extract name and description
            String name = obj.path("name").asText("");
            if (name.isBlank()) {
                throw new StixParseException("Technique " + techniqueId + " is missing required 'name' field");
            }
            String description = obj.path("description").asText("");

            // 8. Extract lowercase kill-chain short names for tactics
            List<String> tactics = extractTactics(obj);

            Technique technique = new Technique(techniqueId, name, description, tactics, isSubTechnique);
            techniques.add(technique);
        }

        logger.debug("Successfully parsed {} active techniques (includeSubTechniques={})",
                techniques.size(), includeSubTechniques);
        return Collections.unmodifiableList(techniques);
    }

    /**
     * Parses a STIX JSON file path into a list of Techniques.
     *
     * @param path                 The path to the STIX JSON file.
     * @param includeSubTechniques Whether to include sub-techniques (true) or parent techniques only (false).
     * @return An unmodifiable List of parsed active Technique objects.
     * @throws StixParseException If JSON syntax is invalid, file is unreadable, or duplicate active technique IDs exist.
     */
    public List<Technique> parse(Path path, boolean includeSubTechniques) {
        if (path == null) {
            throw new StixParseException("STIX file path cannot be null");
        }
        try (InputStream in = Files.newInputStream(path)) {
            return parse(in, includeSubTechniques);
        } catch (IOException e) {
            throw new StixParseException("Unable to open STIX file at path: " + path, e);
        }
    }

    /**
     * Parses a raw STIX JSON string into a list of Techniques.
     *
     * @param jsonString           The raw STIX JSON string.
     * @param includeSubTechniques Whether to include sub-techniques (true) or parent techniques only (false).
     * @return An unmodifiable List of parsed active Technique objects.
     * @throws StixParseException If JSON syntax is invalid or duplicate active technique IDs exist.
     */
    public List<Technique> parse(String jsonString, boolean includeSubTechniques) {
        if (jsonString == null) {
            throw new StixParseException("STIX JSON string cannot be null");
        }
        return parse(new ByteArrayInputStream(jsonString.getBytes(StandardCharsets.UTF_8)), includeSubTechniques);
    }

    /**
     * Parses a STIX JSON input stream into an unmodifiable Map indexed by Technique ID.
     *
     * @param in                   The input stream containing STIX 2.1 JSON.
     * @param includeSubTechniques Whether to include sub-techniques (true) or parent techniques only (false).
     * @return An unmodifiable Map of Technique ID to Technique.
     * @throws StixParseException If JSON syntax is invalid, stream fails to read, or duplicate active technique IDs exist.
     */
    public Map<String, Technique> parseToMap(InputStream in, boolean includeSubTechniques) {
        List<Technique> list = parse(in, includeSubTechniques);
        Map<String, Technique> map = new LinkedHashMap<>();
        for (Technique technique : list) {
            if (map.containsKey(technique.id())) {
                throw new StixParseException("Duplicate active technique ID encountered: " + technique.id());
            }
            map.put(technique.id(), technique);
        }
        return Collections.unmodifiableMap(map);
    }

    /**
     * Parses a STIX JSON file path into an unmodifiable Map indexed by Technique ID.
     *
     * @param path                 The path to the STIX JSON file.
     * @param includeSubTechniques Whether to include sub-techniques (true) or parent techniques only (false).
     * @return An unmodifiable Map of Technique ID to Technique.
     * @throws StixParseException If JSON syntax is invalid, file is unreadable, or duplicate active technique IDs exist.
     */
    public Map<String, Technique> parseToMap(Path path, boolean includeSubTechniques) {
        if (path == null) {
            throw new StixParseException("STIX file path cannot be null");
        }
        try (InputStream in = Files.newInputStream(path)) {
            return parseToMap(in, includeSubTechniques);
        } catch (IOException e) {
            throw new StixParseException("Unable to open STIX file at path: " + path, e);
        }
    }

    /**
     * Extracts the version identifier from the STIX bundle's x-mitre-collection object.
     *
     * @param in The input stream containing STIX JSON.
     * @return The bundle version string, or null if not declared.
     * @throws StixParseException If JSON is malformed or unreadable.
     */
    public String extractBundleVersion(InputStream in) {
        if (in == null) {
            throw new StixParseException("InputStream cannot be null");
        }
        try {
            JsonNode rootNode = mapper.readTree(in);
            if (rootNode == null) {
                return null;
            }
            JsonNode objects = rootNode.get("objects");
            if (objects != null && objects.isArray()) {
                for (JsonNode obj : objects) {
                    if (TYPE_COLLECTION.equals(obj.path("type").asText())) {
                        String version = obj.path("x_mitre_version").asText(null);
                        if (version != null && !version.isBlank()) {
                            return version;
                        }
                    }
                }
            }
            return null;
        } catch (JsonProcessingException e) {
            throw new StixParseException("Malformed JSON while extracting bundle version: " + e.getMessage(), e);
        } catch (IOException e) {
            throw new StixParseException("IO failure while reading bundle for version: " + e.getMessage(), e);
        }
    }

    private String extractTechniqueId(JsonNode obj) {
        JsonNode extRefs = obj.get("external_references");
        if (extRefs != null && extRefs.isArray()) {
            for (JsonNode ref : extRefs) {
                if (MITRE_ATTACK_SOURCE.equals(ref.path("source_name").asText())) {
                    String externalId = ref.path("external_id").asText(null);
                    if (externalId != null && !externalId.isBlank()) {
                        return externalId.trim();
                    }
                }
            }
        }
        return null;
    }

    private List<String> extractTactics(JsonNode obj) {
        JsonNode killChainPhases = obj.get("kill_chain_phases");
        if (killChainPhases == null || !killChainPhases.isArray()) {
            return Collections.emptyList();
        }

        List<String> tactics = new ArrayList<>();
        for (JsonNode phase : killChainPhases) {
            if (MITRE_ATTACK_SOURCE.equals(phase.path("kill_chain_name").asText())) {
                String phaseName = phase.path("phase_name").asText(null);
                if (phaseName != null && !phaseName.isBlank()) {
                    tactics.add(phaseName.trim().toLowerCase(Locale.ROOT));
                }
            }
        }
        return Collections.unmodifiableList(tactics);
    }
}
