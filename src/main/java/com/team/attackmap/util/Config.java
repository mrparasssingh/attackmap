package com.team.attackmap.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Global configuration constants and reproducibility controls for ATT&CK mapping.
 * Contains pinned versions, fixed seeds, and framework identifiers.
 */
public final class Config {

    private static final Logger logger = LoggerFactory.getLogger(Config.class);

    /**
     * Pinned MITRE ATT&CK Enterprise version string.
     * Must never be changed silently.
     */
    public static final String ATTACK_VERSION = "20.0";

    /**
     * Pinned MITRE ATT&CK Enterprise release tag.
     */
    public static final String ATTACK_VERSION_TAG = "v20.0";

    /**
     * STIX Specification version utilized.
     */
    public static final String STIX_SPEC_VERSION = "2.1";

    /**
     * Pinned canonical STIX bundle filename for the pinned ATT&CK Enterprise release.
     */
    public static final String STIX_ENTERPRISE_FILE = "enterprise-attack-20.0.json";

    /**
     * Fixed default random seed for reproducible splits and initializations.
     */
    public static final long DEFAULT_SEED = 42L;

    /**
     * Keyword retrieval weight for a token match in a technique name.
     * Binary-friendly double for exact arithmetic.
     */
    public static final double NAME_WEIGHT = 3.0;

    /**
     * Keyword retrieval weight for a token match in a technique description.
     * Binary-friendly double for exact arithmetic.
     */
    public static final double DESC_WEIGHT = 1.0;

    /**
     * Bonus score added when a technique ID is explicitly mentioned in the
     * input sentence (matched by {@code \bT\d{4}(\.\d{3})?\b}, case-sensitive
     * on the letter T). Set high enough to dominate keyword scores so an
     * explicit ID reference always surfaces the named technique.
     * Binary-friendly double for exact arithmetic.
     */
    public static final double ID_MATCH_BONUS = 100.0;

    /**
     * Minimum valid 0-based sentence index in a report.
     */
    public static final int MIN_SENTENCE_INDEX = 0;

    /**
     * Numeric constant representing zero.
     */
    public static final int ZERO = 0;

    /**
     * Numeric constant representing one.
     */
    public static final int ONE = 1;

    private Config() {
        // Utility configuration class; prevent instantiation.
    }

    /**
     * Logs runtime configuration, pinned versions, and environment details.
     */
    public static void logConfiguration() {
        logger.info("Initializing AttackMap: ATT&CK version={}, STIX spec={}, Seed={}",
                ATTACK_VERSION_TAG, STIX_SPEC_VERSION, DEFAULT_SEED);
        logger.info("Java version={}, Jackson version=2.17.3, JUnit version=5.10.2",
                System.getProperty("java.version"));
    }
}
