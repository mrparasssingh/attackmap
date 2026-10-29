# Execution Flow

## Phase 1: STIX ATT&CK Parsing Flow

```
STIX JSON Input (File / InputStream / Reader)
     |
     v
StixParser.parse(InputStream in, StixParserOptions options)
     |
     |--> Jackson ObjectMapper parses JSON tree (objects array)
     |
     |--> Filter: object.type == "attack-pattern"
     |       |
     |       |--> Check "revoked" is true? If so, SKIP
     |       |--> Check "x_mitre_deprecated" is true? If so, SKIP
     |
     |--> Extract external_references with source_name == "mitre-attack"
     |       |--> external_id is technique ID (e.g. "T1059", "T1059.001")
     |       |--> (If absent, skip or handle invalid object)
     |
     |--> Extract x_mitre_is_subtechnique (boolean flag)
     |       |--> If !options.includeSubTechniques() && isSubTechnique -> SKIP
     |
     |--> Extract name, description
     |--> Extract tactics from kill_chain_phases (where kill_chain_name == "mitre-attack", phase_name)
     |
     v
Technique(id, name, description, tactics, isSubTechnique)
     |
     v
List<Technique> / Map<String, Technique>
```

