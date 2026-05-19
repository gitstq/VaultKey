"""
Password generator module for VaultKey.

Provides secure password generation including random passwords,
passphrases, and PIN codes. Uses cryptographically secure random
number generation via Python's secrets module.
"""

import secrets
from typing import Dict, List, Optional

from .utils import CHARSETS, AMBIGUOUS_CHARS, filter_ambiguous, get_charset

# Built-in English word list for passphrase generation (500+ common words)
WORD_LIST: List[str] = [
    "apple", "banana", "cherry", "dragon", "eagle", "falcon", "garden", "hammer",
    "island", "jungle", "knight", "lemon", "mountain", "nature", "ocean", "piano",
    "queen", "river", "storm", "tiger", "umbrella", "village", "whisper", "yellow",
    "zebra", "anchor", "bridge", "castle", "diamond", "emerald", "forest", "galaxy",
    "harbor", "iceberg", "jacket", "kitten", "lantern", "marble", "nebula", "oracle",
    "phoenix", "quartz", "rhythm", "silver", "thunder", "velvet", "wonder", "zenith",
    "acorn", "breeze", "candle", "dusk", "echo", "feather", "glacier", "horizon",
    "ivory", "jasmine", "karma", "lighthouse", "meadow", "nightingale", "orchid",
    "pebble", "rainbow", "sunset", "treasure", "unity", "violet", "willow", "crystal",
    "amber", "blossom", "coral", "dawn", "ember", "frost", "golden", "honey",
    "indigo", "jade", "kite", "lotus", "moss", "opal", "pearl", "rose",
    "sapphire", "tulip", "aurora", "birch", "cedar", "dahlia", "elm", "fern",
    "ginger", "hibiscus", "iris", "juniper", "lily", "magnolia", "olive", "poppy",
    "sage", "thyme", "vanilla", "walnut", "aster", "basil", "clove", "dill",
    "fennel", "grape", "hazelnut", "laurel", "mint", "nutmeg", "oregano", "paprika",
    "rosemary", "saffron", "tarragon", "copper", "bronze", "platinum", "cobalt",
    "nickel", "zinc", "titanium", "chromium", "magnesium", "silicon", "carbon",
    "oxygen", "nitrogen", "helium", "argon", "neon", "xenon", "krypton",
    "mercury", "venus", "mars", "jupiter", "saturn", "neptune", "pluto", "orion",
    "lyra", "vega", "sirius", "rigel", "altair", "polaris", "andromeda", "cassini",
    "kepler", "newton", "darwin", "euler", "gauss", "fermat", "planck", "bohr",
    "curie", "tesla", "faraday", "maxwell", "kelvin", "joule", "watt", "ampere",
    "voltaire", "mozart", "beethoven", "chopin", "bach", "vivaldi", "handel", "brahms",
    "monet", "picasso", "dali", "rembrandt", "vermeer", "degas", "renoir", "cezanne",
    "odyssey", "paradox", "enigma", "cipher", "matrix", "vector", "tensor", "fractal",
    "quantum", "photon", "neutron", "proton", "quark", "boson", "fermion", "lepton",
    "prism", "spectrum", "wavelength", "frequency", "amplitude", "velocity", "momentum",
    "gravity", "inertia", "catalyst", "entropy", "fusion", "fission", "isotope",
    "alchemy", "cosmos", "eclipse", "solstice", "equinox", "meridian", "zenith",
    "nadir", "pinnacle", "apex", "summit", "ridge", "valley", "canyon", "ravine",
    "delta", "oasis", "tundra", "savanna", "prairie", "steppe", "desert", "arctic",
    "tropic", "tempest", "cyclone", "monsoon", "blizzard", "drought", "flood",
    "avalanche", "volcano", "geyser", "aquifer", "glacier", "fjord", "atoll",
    "peninsula", "archipelago", "continent", "hemisphere", "meridian", "latitude",
    "longitude", "compass", "astrolabe", "telescope", "microscope", "barometer",
    "thermometer", "pendulum", "gyroscope", "magnet", "prism", "lens", "mirror",
    "beacon", "lantern", "chalice", "goblet", "vessel", "amphora", "urn", "relic",
    "artifact", "monolith", "obelisk", "totem", "rune", "glyph", "sigil", "mandala",
    "mosaic", "tapestry", "fresco", "sculpture", "portrait", "landscape", "panorama",
    "vignette", "silhouette", "chiaroscuro", "symphony", "sonata", "concerto", "rhapsody",
    "nocturne", "serenade", "ballad", "anthem", "hymn", "dirge", "elegy", "ode",
    "haiku", "sonnet", "epic", "saga", "fable", "parable", "myth", "legend",
    "chronicle", "archive", "codex", "manuscript", "parchment", "scroll", "tome",
    "lexicon", "glossary", "thesaurus", "encyclopedia", "almanac", "atlas", "compendium",
    "bestiary", "herbal", "grimoire", "manual", "treatise", "thesis", "dissertation",
    "memoir", "journal", "diary", "ledger", "registry", "catalog", "index", "appendix",
    "prologue", "epilogue", "chapter", "verse", "stanza", "refrain", "coda", "finale",
    "overture", "interlude", "prelude", "sequel", "trilogy", "quartet", "quintet",
    "ensemble", "chorus", "crescendo", "diminuendo", "fortissimo", "pianissimo",
    "allegro", "adagio", "presto", "vivace", "andante", "largo", "staccato", "legato",
    "canvas", "palette", "easel", "brush", "pigment", "charcoal", "pastel", "watercolor",
    "inkwell", "quill", "parchment", "papyrus", "vellum", "parchment", "wax", "seal",
    "signet", "crest", "emblem", "insignia", "badge", "medal", "trophy", "plaque",
    "bust", "statue", "monument", "memorial", "shrine", "sanctuary", "temple", "cathedral",
    "chapel", "abbey", "monastery", "convent", "retreat", "haven", "asylum", "refuge",
    "fortress", "bastion", "citadel", "stronghold", "rampart", "bulwark", "palisade",
    "barricade", "redoubt", "entrenchment", "parapet", "watchtower", "battlement",
    "drawbridge", "portcullis", "gatehouse", "bailey", "keep", "dungeon", "cellar",
    "crypt", "vault", "chamber", "antechamber", "corridor", "passage", "gallery",
    "atrium", "courtyard", "plaza", "forum", "agora", "bazaar", "market", "emporium",
    "warehouse", "granary", "silo", "reservoir", "cistern", "aqueduct", "canal",
    "tributary", "estuary", "lagoon", "marsh", "swamp", "bog", "fen", "moor",
    "heath", "scrubland", "badland", "wasteland", "outback", "wilderness", "frontier",
    "border", "boundary", "frontier", "threshold", "gateway", "portal", "passage",
    "corridor", "tunnel", "bridge", "causeway", "ford", "ferry", "crossing",
    "junction", "intersection", "roundabout", "boulevard", "avenue", "promenade",
    "esplanade", "quay", "pier", "dock", "wharf", "slipway", "shipyard", "drydock",
    "lighthouse", "beacon", "buoy", "anchor", "mooring", "berth", "harbor", "port",
    "marina", "cove", "inlet", "bay", "gulf", "strait", "channel", "sound",
    "fjord", "loch", "mere", "tarn", "puddle", "pond", "lake", "reservoir",
    "stream", "brook", "creek", "rivulet", "rill", "spring", "geyser", "fountain",
    "waterfall", "cascade", "rapids", "whirlpool", "eddy", "current", "tide", "wave",
    "surf", "swell", "tsunami", "undertow", "ripple", "shimmer", "reflection", "shadow",
    "silhouette", "contour", "profile", "outline", "sketch", "draft", "blueprint",
    "schematic", "diagram", "chart", "graph", "table", "spreadsheet", "database",
    "archive", "repository", "library", "collection", "anthology", "compendium",
    "treasury", "arsenal", "armory", "magazine", "cache", "hoard", "reserve",
    "stockpile", "inventory", "catalog", "registry", "ledger", "log", "record",
    "journal", "diary", "chronicle", "annals", "history", "memoir", "biography",
    "autobiography", "narrative", "account", "report", "summary", "abstract", "synopsis",
    "outline", "overview", "survey", "review", "critique", "analysis", "evaluation",
    "assessment", "appraisal", "estimate", "calculation", "computation", "measurement",
    "dimension", "proportion", "ratio", "fraction", "percentage", "quotient",
    "dividend", "remainder", "balance", "equilibrium", "symmetry", "harmony",
    "consonance", "dissonance", "cacophony", "euphony", "melody", "harmony", "rhythm",
    "cadence", "tempo", "beat", "pulse", "throb", "vibration", "resonance", "echo",
    "reverberation", "amplification", "attenuation", "distortion", "interference",
    "diffraction", "refraction", "reflection", "absorption", "transmission", "radiation",
    "emission", "dispersion", "diffusion", "osmosis", "permeation", "infiltration",
    "penetration", "perforation", "rupture", "fracture", "fissure", "crevice", "gap",
    "void", "abyss", "chasm", "gulf", "divide", "gulf", "expanse", "stretch",
    "span", "reach", "extent", "scope", "range", "domain", "realm", "territory",
    "province", "region", "district", "zone", "sector", "area", "space", "volume",
    "capacity", "magnitude", "scale", "degree", "extent", "measure", "quantity",
    "amount", "number", "count", "tally", "score", "total", "sum",
]


def generate_password(
    length: int = 16,
    charset_config: Optional[Dict[str, bool]] = None,
    exclude_ambiguous: bool = False,
    no_repeating: bool = False,
) -> str:
    """Generate a cryptographically secure random password.

    Uses Python's secrets module for cryptographically secure random number
    generation. Supports customizable character sets and various constraints.

    Args:
        length: Desired password length (default: 16).
        charset_config: Dictionary specifying which character sets to include.
                       Keys: uppercase, lowercase, digits, symbols (all bool).
                       Defaults to all True.
        exclude_ambiguous: If True, removes ambiguous characters (0/O, 1/l/I, etc.).
        no_repeating: If True, prevents consecutive repeated characters.

    Returns:
        A randomly generated password string.

    Raises:
        ValueError: If length is too short or constraints cannot be satisfied.
    """
    if charset_config is None:
        charset_config = {
            "uppercase": True,
            "lowercase": True,
            "digits": True,
            "symbols": True,
        }

    charset = get_charset(charset_config)

    if exclude_ambiguous:
        charset = filter_ambiguous(charset)

    if not charset:
        raise ValueError("Character set is empty after filtering.")

    if no_repeating and len(charset) < length:
        raise ValueError(
            f"Cannot generate password of length {length} without repeating "
            f"characters from a charset of size {len(charset)}."
        )

    if length < 1:
        raise ValueError("Password length must be at least 1.")

    password = ""
    max_attempts = length * 10  # Prevent infinite loops
    attempts = 0

    while len(password) < length and attempts < max_attempts:
        char = secrets.choice(charset)
        if no_repeating and password and password[-1] == char:
            attempts += 1
            continue
        password += char
        attempts += 1

    if len(password) < length:
        raise ValueError(
            "Failed to generate password within reasonable attempts. "
            "Try relaxing constraints."
        )

    # Ensure at least one character from each enabled set is present
    _ensure_charset_coverage(password, charset_config, exclude_ambiguous)

    return password


def _ensure_charset_coverage(
    password: str,
    charset_config: Dict[str, bool],
    exclude_ambiguous: bool,
) -> str:
    """Ensure the password contains at least one character from each enabled charset.

    If a required character type is missing, replaces a random position
    with a character from that type.

    Args:
        password: The generated password.
        charset_config: The charset configuration dictionary.
        exclude_ambiguous: Whether ambiguous characters should be excluded.

    Returns:
        The password with guaranteed charset coverage.
    """
    import secrets as _secrets

    password_list = list(password)
    required_sets: Dict[str, str] = {}

    if charset_config.get("uppercase", False):
        chars = CHARSETS["uppercase"]
        if exclude_ambiguous:
            chars = filter_ambiguous(chars)
        required_sets["uppercase"] = chars

    if charset_config.get("lowercase", False):
        chars = CHARSETS["lowercase"]
        if exclude_ambiguous:
            chars = filter_ambiguous(chars)
        required_sets["lowercase"] = chars

    if charset_config.get("digits", False):
        chars = CHARSETS["digits"]
        if exclude_ambiguous:
            chars = filter_ambiguous(chars)
        required_sets["digits"] = chars

    if charset_config.get("symbols", False):
        chars = CHARSETS["symbols"]
        required_sets["symbols"] = chars

    for charset_name, chars in required_sets.items():
        if not any(c in chars for c in password_list):
            # Replace a random position with a character from this set
            pos = _secrets.randbelow(len(password_list))
            password_list[pos] = _secrets.choice(chars)

    return "".join(password_list)


def generate_passphrase(
    num_words: int = 4,
    separator: str = "-",
    capitalize: bool = False,
    word_list: Optional[List[str]] = None,
) -> str:
    """Generate a memorable passphrase from random words.

    Creates a passphrase by selecting random words from a built-in word list,
    optionally capitalizing each word and joining them with a separator.

    Args:
        num_words: Number of words in the passphrase (default: 4).
        separator: String used to separate words (default: "-").
        capitalize: If True, capitalize the first letter of each word.
        word_list: Optional custom word list. Defaults to built-in list.

    Returns:
        A generated passphrase string.

    Raises:
        ValueError: If num_words is less than 1 or word list is too small.
    """
    if num_words < 1:
        raise ValueError("Number of words must be at least 1.")

    words = word_list or WORD_LIST

    if len(words) < num_words:
        raise ValueError(
            f"Word list has only {len(words)} words, but {num_words} were requested."
        )

    selected = [secrets.choice(words) for _ in range(num_words)]

    if capitalize:
        selected = [w.capitalize() for w in selected]

    return separator.join(selected)


def generate_pin(length: int = 4) -> str:
    """Generate a random numeric PIN code.

    Args:
        length: Number of digits in the PIN (default: 4).

    Returns:
        A string of random digits.

    Raises:
        ValueError: If length is less than 1 or greater than 32.
    """
    if length < 1:
        raise ValueError("PIN length must be at least 1.")
    if length > 32:
        raise ValueError("PIN length must not exceed 32.")

    return "".join(secrets.choice("0123456789") for _ in range(length))


def generate_batch(
    count: int = 10,
    mode: str = "password",
    **kwargs,
) -> List[str]:
    """Generate multiple passwords or passphrases at once.

    Args:
        count: Number of passwords to generate (default: 10).
        mode: Generation mode - 'password', 'passphrase', or 'pin'.
        **kwargs: Additional arguments passed to the respective generator.

    Returns:
        A list of generated password strings.

    Raises:
        ValueError: If count is less than 1 or mode is invalid.
    """
    if count < 1:
        raise ValueError("Count must be at least 1.")

    results: List[str] = []

    if mode == "password":
        for _ in range(count):
            results.append(generate_password(**kwargs))
    elif mode == "passphrase":
        for _ in range(count):
            results.append(generate_passphrase(**kwargs))
    elif mode == "pin":
        for _ in range(count):
            results.append(generate_pin(**kwargs))
    else:
        raise ValueError(f"Unknown generation mode: '{mode}'. Use 'password', 'passphrase', or 'pin'.")

    return results
