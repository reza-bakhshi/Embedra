#!/usr/bin/env python3
"""Generate Embedra's offline ESP catalog from pinned normalized vendor facts."""

from __future__ import annotations

import argparse
import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import tempfile
from typing import Any


FACTS_SCHEMA = "urn:embedra:schema:esp-catalog-source-facts:1"
CATALOG_SCHEMA = "urn:embedra:schema:esp-device-catalog:1"
GENERATOR_VERSION = "embedra-esp-catalog-generator-v1"
MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_RECORDS = 10_000
REQUIRED_SERIES = {
    "ESP32", "ESP32-S2", "ESP32-S3", "ESP32-S31", "ESP32-P4", "ESP32-C2",
    "ESP32-C3", "ESP32-C5", "ESP32-C6", "ESP32-C61", "ESP32-E22",
    "ESP32-H2", "ESP32-H21", "ESP32-H4",
}


class SourceError(ValueError):
    """A vendor input violated the bounded source contract."""


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, separators=(",", ":"),
                       sort_keys=True) + "\n").encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def normalized_text(parts: list[str]) -> str:
    return " ".join(" ".join(parts).replace("®", "").split())


class _ProductPageParser(HTMLParser):
    VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img", "input",
                 "link", "meta", "param", "source", "track", "wbr"}

    def __init__(self, page_kind: str, max_depth: int):
        super().__init__(convert_charrefs=True)
        self.page_kind = page_kind
        self.max_depth = max_depth
        self.stack: list[tuple[str, set[str]]] = []
        self.active_fields: list[dict[str, Any]] = []
        self.row_depth = 0
        self.current_record: dict[str, Any] | None = None
        self.current_series = ""
        self.current_description = ""
        self.records: list[dict[str, Any]] = []

    def handle_decl(self, decl: str) -> None:
        raise SourceError("Document declarations are not permitted in catalog HTML")

    def unknown_decl(self, data: str) -> None:
        raise SourceError("Unknown declarations are not permitted in catalog HTML")

    def handle_entityref(self, name: str) -> None:
        raise SourceError("Entity references are not permitted in catalog HTML")

    def handle_charref(self, name: str) -> None:
        raise SourceError("Character references must be decoded by the HTML parser")

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        classes = set((attributes.get("class") or "").split())
        self.stack.append((tag, classes))
        if len(self.stack) > self.max_depth:
            raise SourceError("Catalog HTML exceeds the configured nesting limit")
        if tag == "tr" and "sheet-item" in classes:
            if self.row_depth == 0:
                self.current_record = {
                    "series": self.current_series,
                    "seriesDescription": self.current_description,
                }
            self.row_depth += 1
        for field in sorted(classes):
            if self._wanted_field(field):
                self.active_fields.append({
                    "tag": tag,
                    "depth": len(self.stack),
                    "field": field,
                    "parts": [],
                })
        if tag in self.VOID_TAGS:
            self.handle_endtag(tag)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        if tag not in self.VOID_TAGS:
            self.handle_endtag(tag)

    def handle_data(self, data: str) -> None:
        if data.strip():
            for active in self.active_fields:
                active["parts"].append(data)

    def handle_endtag(self, tag: str) -> None:
        depth = len(self.stack)
        closing_classes = self.stack[-1][1] if self.stack and self.stack[-1][0] == tag else set()
        closing = [field for field in self.active_fields
                   if field["depth"] == depth and field["tag"] == tag]
        for field in closing:
            self.active_fields.remove(field)
            value = normalized_text(field["parts"])
            if value:
                self._store_field(field["field"], value)
        if tag == "tr" and "sheet-item" in closing_classes and self.row_depth:
            self.row_depth -= 1
            if self.row_depth == 0 and self.current_record is not None:
                if len(self.records) >= MAX_RECORDS:
                    raise SourceError("Catalog HTML exceeds the record limit")
                self.records.append(self.current_record)
                self.current_record = None
        if self.stack:
            self.stack.pop()

    def _store_field(self, field: str, value: str) -> None:
        if field == "sheet-category-name":
            self.current_series = value
            return
        if field == "sheet-category-desc":
            self.current_description = value
            return
        if self.current_record is None:
            return
        if field == "purchase-pn-text":
            self.current_record.setdefault(field, []).append(value)
        elif field not in self.current_record:
            self.current_record[field] = value

    def _wanted_field(self, field: str) -> bool:
        prefixes = {
            "soc": ("chip-",),
            "module": ("module-",),
            "board": ("devbd-",),
        }
        exact = {"sheet-category-name", "sheet-category-desc", "purchase-pn-text"}
        return field in exact or field.startswith(prefixes[self.page_kind])


def parse_product_page(text: str, page_kind: str, max_depth: int = 96) -> list[dict[str, Any]]:
    if page_kind not in {"soc", "module", "board"}:
        raise SourceError("Unknown Espressif product page kind")
    encoded = text.encode("utf-8")
    if len(encoded) > MAX_SOURCE_BYTES:
        raise SourceError("Catalog HTML exceeds the input byte limit")
    upper = text.upper()
    if "<!DOCTYPE" in upper or "<!ENTITY" in upper:
        raise SourceError("DTD and entity declarations are not permitted")
    parser = _ProductPageParser(page_kind, max_depth)
    parser.feed(text)
    parser.close()
    if parser.stack or parser.row_depth:
        raise SourceError("Catalog HTML has unclosed structural elements")
    if not parser.records:
        raise SourceError("Catalog HTML contains no product rows")
    return parser.records


def _read_bounded(path: Path) -> bytes:
    size = path.stat().st_size
    if size > MAX_SOURCE_BYTES:
        raise SourceError(f"Source exceeds {MAX_SOURCE_BYTES} bytes: {path.name}")
    return path.read_bytes()


def _read_official_html(path: Path) -> str:
    text = _read_bounded(path).decode("utf-8")
    # Espressif emits one leading legacy XHTML DOCTYPE. HTMLParser never
    # resolves it; remove exactly the leading declaration before parsing.
    # Any later declaration or entity remains rejected.
    return re.sub(r"\A\s*<!DOCTYPE[^>]*>\s*", "", text, count=1,
                  flags=re.I | re.S)


def _clean_part(value: str) -> tuple[str, str]:
    lifecycle = "ACTIVE"
    if value.endswith(" (EOL)"):
        value = value[:-6]
        lifecycle = "EOL"
    elif value.endswith(" (Sample)"):
        value = value[:-9]
        lifecycle = "SAMPLE"
    return value.strip(), lifecycle


def _series_target(series: str) -> str:
    return series.lower().replace("-", "")


def _parse_int(value: str) -> int:
    match = re.search(r"\d+", value)
    if not match:
        raise SourceError(f"Expected integer in vendor value: {value}")
    return int(match.group())


def _parse_idf(idf_root: Path) -> dict[str, dict[str, Any]]:
    kconfig = _read_bounded(idf_root / "Kconfig").decode("utf-8")
    architectures: dict[str, str] = {}
    chip_ids: dict[str, str] = {}
    current = ""
    for line in kconfig.splitlines():
        match = re.match(r"\s*config IDF_TARGET_([A-Z0-9]+)$", line)
        if match:
            current = match.group(1).lower()
            continue
        if current and "select IDF_TARGET_ARCH_XTENSA" in line:
            architectures[current] = "XTENSA"
        elif current and "select IDF_TARGET_ARCH_RISCV" in line:
            architectures[current] = "RISCV"
        match = re.match(r"\s*default 0x([0-9A-Fa-f]+) if IDF_TARGET_([A-Z0-9]+)", line)
        if match:
            chip_ids[match.group(2).lower()] = str(int(match.group(1), 16))
    result: dict[str, dict[str, Any]] = {}
    soc_root = idf_root / "components" / "soc"
    for target, isa in architectures.items():
        caps_path = soc_root / target / "include" / "soc" / "soc_caps.h"
        if not caps_path.is_file():
            continue
        caps = _read_bounded(caps_path).decode("utf-8")
        core_match = re.search(r"^#define\s+SOC_CPU_CORES_NUM\s+\(?([0-9]+)", caps, re.M)
        enabled = sorted(set(re.findall(
            r"^#define\s+(SOC_[A-Z0-9_]+)\s+\(?1(?:U)?\)?(?:\s|$)", caps, re.M)))
        supported = [name for name in enabled if name.endswith("SUPPORTED")]
        security_tokens = (
            "AES", "SHA", "RSA", "ECC", "ECDSA", "HMAC", "DIG_SIGN",
            "SECURE", "FLASH_ENCRYPTION", "RNG",
        )
        peripheral_tokens = (
            "UART", "SPI", "I2C", "I2S", "GPIO", "ADC", "DAC", "DMA", "USB",
            "LCD", "CAM", "TWAI", "CAN", "LEDC", "MCPWM", "RMT", "SDM",
            "SDIO", "SDMMC", "ETH", "WIFI", "BT", "IEEE802154", "TOUCH",
            "PCNT", "TIMER", "TEMP", "SAR", "PARLIO", "JPEG", "MIPI", "ISP",
            "UHCI",
        )
        auxiliaries: list[str] = []
        if re.search(r"^#define\s+SOC_RISCV_COPROC_SUPPORTED\s+1", caps, re.M):
            auxiliaries.append("ULP_RISCV")
        if re.search(r"^#define\s+SOC_LP_CORE_SUPPORTED\s+1", caps, re.M):
            auxiliaries.append("LP_RISCV")
        if (re.search(r"^#define\s+SOC_ULP_FSM_SUPPORTED\s+1", caps, re.M)
                and "ULP_RISCV" not in auxiliaries):
            auxiliaries.append("ULP_FSM")
        result[target] = {
            "isa": isa,
            "applicationCoreCount": int(core_match.group(1)) if core_match else 0,
            "auxiliaryProcessors": sorted(auxiliaries),
            "firmwareChipId": chip_ids.get(target, "UNKNOWN"),
            "socCapsPath": str(caps_path.relative_to(idf_root)),
            "socCapabilityMacros": supported,
            "peripheralCapabilities": [name for name in enabled
                                       if any(token in name for token in peripheral_tokens)],
            "securityCapabilities": [name for name in enabled
                                     if any(token in name for token in security_tokens)],
        }
    return result


def _topology(series: str, description: str,
              idf: dict[str, dict[str, Any]]) -> dict[str, Any]:
    target = _series_target(series)
    if target in idf:
        return idf[target]
    isa = "RISCV" if "RISC-V" in description else "XTENSA"
    cores = 2 if "Dual-core" in description else 1 if "Single-core" in description else 0
    if not cores:
        raise SourceError(f"Missing processor topology for {series}")
    return {
        "isa": isa,
        "applicationCoreCount": cores,
        "auxiliaryProcessors": [],
        "firmwareChipId": "UNKNOWN",
        "socCapsPath": "UNAVAILABLE_IN_PINNED_IDF",
        "socCapabilityMacros": [],
        "peripheralCapabilities": [],
        "securityCapabilities": [],
    }


def _source(path: Path, identity: str, url: str, license_id: str,
            revision: str) -> dict[str, str]:
    content = _read_bounded(path)
    return {
        "identity": identity,
        "url": url,
        "revision": revision,
        "sha256": sha256_bytes(content),
        "license": license_id,
        "redistribution": "DERIVED_FACTS_ONLY" if identity != "esp-idf" else "ALLOWED",
    }


def _idf_input_digest(idf_root: Path, topology: dict[str, dict[str, Any]]) -> str:
    digest = hashlib.sha256()
    paths = [Path("Kconfig")]
    paths.extend(Path(value["socCapsPath"]) for value in topology.values())
    for relative in sorted(set(paths), key=lambda value: value.as_posix()):
        content = _read_bounded(idf_root / relative)
        digest.update(relative.as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(len(content)).encode("ascii"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(content).hexdigest().encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def ingest(socs_path: Path, modules_path: Path, boards_path: Path, idf_root: Path,
           snapshot_date: str, output: Path) -> dict[str, Any]:
    soc_rows = parse_product_page(_read_official_html(socs_path), "soc")
    module_rows = parse_product_page(_read_official_html(modules_path), "module")
    board_rows = parse_product_page(_read_official_html(boards_path), "board")
    idf_revision = _read_bounded(idf_root / ".git" / "HEAD").decode("utf-8").strip()
    if idf_revision.startswith("ref:"):
        ref = idf_revision.split(" ", 1)[1]
        idf_revision = _read_bounded(idf_root / ".git" / ref).decode("utf-8").strip()
    idf = _parse_idf(idf_root)
    sources = [
        _source(socs_path, "espressif-soc-catalog",
                "https://www.espressif.com/en/products/socs",
                "LicenseRef-Espressif-Public-Product-Facts", snapshot_date),
        _source(modules_path, "espressif-module-catalog",
                "https://www.espressif.com/en/products/modules",
                "LicenseRef-Espressif-Public-Product-Facts", snapshot_date),
        _source(boards_path, "espressif-development-board-catalog",
                "https://www.espressif.com/en/products/devkits",
                "LicenseRef-Espressif-Public-Product-Facts", snapshot_date),
        {
            "identity": "esp-idf",
            "url": "https://github.com/espressif/esp-idf",
            "revision": idf_revision,
            "sha256": _idf_input_digest(idf_root, idf),
            "license": "Apache-2.0",
            "redistribution": "ALLOWED",
        },
    ]

    silicon: list[dict[str, Any]] = []
    last_name_by_series: dict[str, str] = {}
    for row in soc_rows:
        series = row.get("series", "")
        if series == "ESP8266":
            continue
        name = row.get("chip-name") or last_name_by_series.get(series, "")
        if name:
            last_name_by_series[series] = name
        part, lifecycle = _clean_part(row.get("chip-variants", ""))
        if not part or series not in REQUIRED_SERIES:
            continue
        topology = _topology(series, row.get("seriesDescription", ""), idf)
        silicon.append({
            "series": series,
            "marketingName": name,
            "exactPart": part,
            "package": row.get("chip-package", "UNKNOWN").replace("×", "x"),
            "pins": row.get("chip-pins", "UNKNOWN"),
            "ramKb": row.get("chip-ram", "UNKNOWN"),
            "embeddedFlashMb": row.get("chip-flash", "UNKNOWN"),
            "embeddedPsramMb": row.get("chip-psram", "UNKNOWN"),
            "lifecycle": lifecycle,
            "siliconRevision": (
                re.search(r"Chip revision ([^)]+)", name).group(1)
                if re.search(r"Chip revision ([^)]+)", name) else "UNSPECIFIED"
            ),
            "romIdentity": "UNKNOWN",
            **topology,
        })
    known_parts = {record["exactPart"] for record in silicon}
    by_series: dict[str, list[str]] = {}
    for record in silicon:
        by_series.setdefault(record["series"], []).append(record["exactPart"])

    modules: list[dict[str, Any]] = []
    for row in module_rows:
        series = row.get("series", "")
        if series == "ESP8266" or series not in REQUIRED_SERIES:
            continue
        candidates = [part.strip() for part in row.get("module-family", "").split(",")
                      if part.strip() in known_parts]
        if not candidates:
            candidates = by_series.get(series, [])
        parts = row.get("purchase-pn-text") or [row.get("module-name", "")]
        for part in sorted(set(parts)):
            if part:
                modules.append({
                    "series": series,
                    "profileName": row.get("module-name", part),
                    "exactPart": part,
                    "package": row.get("module-package", "UNKNOWN").replace("×", "x"),
                    "flashMb": row.get("module-flash", "UNKNOWN"),
                    "psramMb": row.get("module-psram", "UNKNOWN"),
                    "siliconParts": sorted(set(candidates)),
                })

    boards: list[dict[str, Any]] = []
    for row in board_rows:
        series = row.get("series", "")
        if series == "ESP8266" or series not in REQUIRED_SERIES:
            continue
        description = row.get("devbd-desc", "")
        mentioned = [part for part in known_parts if part in description]
        candidates = mentioned or by_series.get(series, [])
        parts = row.get("purchase-pn-text") or [row.get("devbd-name", "")]
        for part in sorted(set(parts)):
            if part:
                boards.append({
                    "series": series,
                    "profileName": row.get("devbd-name", part),
                    "exactPart": part,
                    "flashMb": row.get("devbd-flash", "UNKNOWN"),
                    "psramMb": row.get("devbd-psram", "UNKNOWN"),
                    "siliconParts": sorted(set(candidates)),
                })
    if {record["series"] for record in silicon} != REQUIRED_SERIES:
        missing = sorted(REQUIRED_SERIES - {record["series"] for record in silicon})
        raise SourceError(f"Mandatory official series missing: {missing}")
    if any(not profile["siliconParts"] for profile in modules + boards):
        raise SourceError("Every module and board profile must reference cataloged silicon")
    facts = {
        "schemaId": FACTS_SCHEMA,
        "snapshotDate": snapshot_date,
        "generator": GENERATOR_VERSION,
        "sources": sorted(sources, key=lambda value: value["identity"]),
        "silicon": sorted(silicon, key=lambda value: value["exactPart"]),
        "modules": sorted(modules, key=lambda value: value["exactPart"]),
        "boards": sorted(boards, key=lambda value: value["exactPart"]),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(canonical_bytes(facts))
    return facts


def _record_id(kind: str, exact_part: str) -> str:
    return f"espressif:{kind.lower()}:{exact_part.lower()}"


def _support_states() -> dict[str, str]:
    return {"catalog": "PLANNED", "firmware-import": "PLANNED",
            "topology": "PLANNED"}


def _validate_facts(facts: dict[str, Any]) -> None:
    if facts.get("schemaId") != FACTS_SCHEMA:
        raise SourceError("Unsupported ESP catalog source-facts schema")
    if not facts.get("sources") or not facts.get("silicon"):
        raise SourceError("ESP catalog facts are incomplete")
    if {record["series"] for record in facts["silicon"]} != REQUIRED_SERIES:
        raise SourceError("ESP catalog facts do not cover the mandatory series set")
    exact_parts = [record["exactPart"] for group in ("silicon", "modules", "boards")
                   for record in facts[group]]
    if len(exact_parts) != len(set((group, record["exactPart"])
                                  for group in ("silicon", "modules", "boards")
                                  for record in facts[group])):
        raise SourceError("Duplicate exact part within an ESP entity kind")


def generate(facts_path: Path, output: Path) -> dict[str, Any]:
    raw = _read_bounded(facts_path)
    try:
        facts = json.loads(raw)
    except json.JSONDecodeError as exception:
        raise SourceError("Source facts are not valid JSON") from exception
    _validate_facts(facts)
    silicon_ids = {record["exactPart"]: _record_id("silicon", record["exactPart"])
                   for record in facts["silicon"]}
    records: list[dict[str, Any]] = []
    for source in facts["silicon"]:
        records.append({
            "recordId": silicon_ids[source["exactPart"]],
            "kind": "SILICON",
            "series": source["series"],
            "exactPart": source["exactPart"],
            "package": source["package"],
            "isa": source["isa"],
            "applicationCoreCount": source["applicationCoreCount"],
            "auxiliaryProcessors": source["auxiliaryProcessors"],
            "embeddedFlashMb": source["embeddedFlashMb"],
            "embeddedPsramMb": source["embeddedPsramMb"],
            "lifecycle": source["lifecycle"],
            "siliconRevision": source["siliconRevision"],
            "firmwareChipId": source["firmwareChipId"],
            "romIdentity": source["romIdentity"],
            "topologyEvidence": source["socCapsPath"],
            "socCapabilityMacros": source["socCapabilityMacros"],
            "peripheralCapabilities": source["peripheralCapabilities"],
            "securityCapabilities": source["securityCapabilities"],
            "siliconRecordIds": [],
            "supportStates": _support_states(),
        })
    for group, kind in (("modules", "MODULE"), ("boards", "BOARD")):
        for source in facts[group]:
            records.append({
                "recordId": _record_id(kind, source["exactPart"]),
                "kind": kind,
                "series": source["series"],
                "exactPart": source["exactPart"],
                "package": source.get("package", "BOARD"),
                "isa": "PROFILE",
                "applicationCoreCount": 0,
                "auxiliaryProcessors": [],
                "embeddedFlashMb": source.get("flashMb", "UNKNOWN"),
                "embeddedPsramMb": source.get("psramMb", "UNKNOWN"),
                "lifecycle": "ACTIVE",
                "siliconRevision": "PROFILE",
                "firmwareChipId": "PROFILE",
                "romIdentity": "PROFILE",
                "topologyEvidence": "PROFILE_REFERENCES_EXACT_SILICON",
                "socCapabilityMacros": [],
                "peripheralCapabilities": [],
                "securityCapabilities": [],
                "siliconRecordIds": sorted(silicon_ids[part]
                                           for part in source["siliconParts"]),
                "supportStates": _support_states(),
            })
    records.sort(key=lambda value: value["recordId"])
    catalog = {
        "schemaId": CATALOG_SCHEMA,
        "catalogId": "espressif.esp32-family",
        "snapshotDate": facts["snapshotDate"],
        "generator": GENERATOR_VERSION,
        "sourceFactsSha256": sha256_bytes(raw),
        "sources": facts["sources"],
        "records": records,
    }
    output.mkdir(parents=True, exist_ok=True)
    content = canonical_bytes(catalog)
    (output / "catalog.json").write_bytes(content)
    (output / "catalog.sha256").write_text(
        f"{sha256_bytes(content)}  catalog.json\n", encoding="utf-8")
    return catalog


def diff_catalogs(previous: dict[str, Any], current: dict[str, Any]) -> dict[str, list[str]]:
    old = {record["recordId"]: record for record in previous["records"]}
    new = {record["recordId"]: record for record in current["records"]}
    return {
        "added": sorted(new.keys() - old.keys()),
        "removed": sorted(old.keys() - new.keys()),
        "changed": sorted(key for key in old.keys() & new.keys() if old[key] != new[key]),
    }


def check(facts: Path, catalog_dir: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="embedra-esp-catalog-") as temporary:
        generated = Path(temporary)
        generate(facts, generated)
        for name in ("catalog.json", "catalog.sha256"):
            if (generated / name).read_bytes() != (catalog_dir / name).read_bytes():
                raise SourceError(f"Committed ESP catalog is stale: {name}")


def drift(socs: Path, modules: Path, boards: Path, idf: Path, baseline: Path,
          snapshot_date: str, output: Path) -> dict[str, list[str]]:
    with tempfile.TemporaryDirectory(prefix="embedra-esp-drift-") as temporary:
        temporary_path = Path(temporary)
        candidate_facts = temporary_path / "source-facts.json"
        candidate_catalog = temporary_path / "catalog"
        baseline_catalog = temporary_path / "baseline"
        ingest(socs, modules, boards, idf, snapshot_date, candidate_facts)
        current = generate(candidate_facts, candidate_catalog)
        previous = generate(baseline, baseline_catalog)
        result = diff_catalogs(previous, current)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(canonical_bytes(result))
        candidate_output = output.with_name("candidate-source-facts.json")
        candidate_output.write_bytes(candidate_facts.read_bytes())
        return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    ingest_command = commands.add_parser("ingest")
    ingest_command.add_argument("--socs", type=Path, required=True)
    ingest_command.add_argument("--modules", type=Path, required=True)
    ingest_command.add_argument("--boards", type=Path, required=True)
    ingest_command.add_argument("--idf", type=Path, required=True)
    ingest_command.add_argument("--snapshot-date", required=True)
    ingest_command.add_argument("--output", type=Path, required=True)
    generate_command = commands.add_parser("generate")
    generate_command.add_argument("--facts", type=Path, required=True)
    generate_command.add_argument("--output", type=Path, required=True)
    check_command = commands.add_parser("check")
    check_command.add_argument("--facts", type=Path, required=True)
    check_command.add_argument("--catalog", type=Path, required=True)
    drift_command = commands.add_parser("drift")
    drift_command.add_argument("--socs", type=Path, required=True)
    drift_command.add_argument("--modules", type=Path, required=True)
    drift_command.add_argument("--boards", type=Path, required=True)
    drift_command.add_argument("--idf", type=Path, required=True)
    drift_command.add_argument("--baseline", type=Path, required=True)
    drift_command.add_argument("--snapshot-date", required=True)
    drift_command.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "ingest":
        ingest(args.socs, args.modules, args.boards, args.idf, args.snapshot_date, args.output)
    elif args.command == "generate":
        generate(args.facts, args.output)
    elif args.command == "check":
        check(args.facts, args.catalog)
    else:
        result = drift(args.socs, args.modules, args.boards, args.idf,
                       args.baseline, args.snapshot_date, args.output)
        if any(result.values()):
            raise SystemExit(3)


if __name__ == "__main__":
    main()
