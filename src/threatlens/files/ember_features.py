"""
EMBER 2018 v2 feature extraction — 2381 features from a PE (Portable
Executable) file, for malware detection.

Ported from elastic/ember (https://github.com/elastic/ember) for Python 3.12+
and LIEF >= 0.15 compatibility. Requires ``lief`` for PE parsing and
scikit-learn's ``FeatureHasher``.
"""

from __future__ import annotations

import hashlib
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

logger = logging.getLogger(__name__)

try:
    import lief
    LIEF_AVAILABLE = True
    _major, _minor, *_ = lief.__version__.split(".")
    LIEF_MAJOR, LIEF_MINOR = int(_major), int(_minor)
    LIEF_EXPORT_OBJECT = LIEF_MAJOR > 0 or (LIEF_MAJOR == 0 and LIEF_MINOR >= 10)
    LIEF_HAS_SIGNATURE = LIEF_MAJOR > 0 or (LIEF_MAJOR == 0 and LIEF_MINOR >= 11)
except ImportError:
    LIEF_AVAILABLE = False
    LIEF_MAJOR = LIEF_MINOR = 0
    LIEF_EXPORT_OBJECT = LIEF_HAS_SIGNATURE = False

try:
    from sklearn.feature_extraction import FeatureHasher
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


class FeatureType:
    name = ""
    dim = 0

    def raw_features(self, bytez: bytes, lief_binary) -> Any:
        raise NotImplementedError

    def process_raw_features(self, raw_obj: Any) -> np.ndarray:
        raise NotImplementedError

    def feature_vector(self, bytez: bytes, lief_binary) -> np.ndarray:
        return self.process_raw_features(self.raw_features(bytez, lief_binary))


class ByteHistogram(FeatureType):
    name = "histogram"
    dim = 256

    def raw_features(self, bytez, lief_binary):
        return np.bincount(np.frombuffer(bytez, dtype=np.uint8), minlength=256).tolist()

    def process_raw_features(self, raw_obj):
        counts = np.array(raw_obj, dtype=np.float32)
        total = counts.sum()
        return counts / total if total > 0 else counts


class ByteEntropyHistogram(FeatureType):
    name = "byteentropy"
    dim = 256

    def __init__(self, step: int = 1024, window: int = 2048):
        self.window = window
        self.step = step

    def _entropy_bin_counts(self, block):
        c = np.bincount(block >> 4, minlength=16)
        p = c.astype(np.float32) / self.window
        wh = np.where(c)[0]
        H = np.sum(-p[wh] * np.log2(p[wh])) * 2 if len(wh) > 0 else 0.0
        Hbin = int(H * 2)
        if Hbin == 16:
            Hbin = 15
        return Hbin, c

    def raw_features(self, bytez, lief_binary):
        output = np.zeros((16, 16), dtype=np.int64)
        a = np.frombuffer(bytez, dtype=np.uint8)
        if a.shape[0] < self.window:
            Hbin, c = self._entropy_bin_counts(a)
            output[Hbin, :] += c
        else:
            shape = a.shape[:-1] + (a.shape[-1] - self.window + 1, self.window)
            strides = a.strides + (a.strides[-1],)
            blocks = np.lib.stride_tricks.as_strided(a, shape=shape, strides=strides)[::self.step, :]
            for block in blocks:
                Hbin, c = self._entropy_bin_counts(block)
                output[Hbin, :] += c
        return output.flatten().tolist()

    def process_raw_features(self, raw_obj):
        counts = np.array(raw_obj, dtype=np.float32)
        total = counts.sum()
        return counts / total if total > 0 else counts


class StringExtractor(FeatureType):
    name = "strings"
    dim = 104

    def __init__(self):
        self._allstrings = re.compile(b"[\x20-\x7f]{5,}")
        self._paths = re.compile(b"c:\\\\", re.IGNORECASE)
        self._urls = re.compile(b"https?://", re.IGNORECASE)
        self._registry = re.compile(b"HKEY_")
        self._mz = re.compile(b"MZ")

    def raw_features(self, bytez, lief_binary):
        allstrings = self._allstrings.findall(bytez)
        if allstrings:
            string_lengths = [len(s) for s in allstrings]
            avlength = sum(string_lengths) / len(string_lengths)
            as_shifted = [b - ord(b"\x20") for b in b"".join(allstrings)]
            c = np.bincount(as_shifted, minlength=96)
            csum = c.sum()
            p = c.astype(np.float32) / csum if csum > 0 else c.astype(np.float32)
            wh = np.where(c)[0]
            H = np.sum(-p[wh] * np.log2(p[wh])) if len(wh) > 0 else 0.0
        else:
            avlength = 0
            c = np.zeros((96,), dtype=np.float32)
            H = 0
            csum = 0
        return {
            "numstrings": len(allstrings), "avlength": avlength,
            "printabledist": c.tolist(), "printables": int(csum),
            "entropy": float(H), "paths": len(self._paths.findall(bytez)),
            "urls": len(self._urls.findall(bytez)),
            "registry": len(self._registry.findall(bytez)),
            "MZ": len(self._mz.findall(bytez)),
        }

    def process_raw_features(self, raw_obj):
        divisor = float(raw_obj["printables"]) if raw_obj["printables"] > 0 else 1.0
        return np.hstack([
            raw_obj["numstrings"], raw_obj["avlength"], raw_obj["printables"],
            np.asarray(raw_obj["printabledist"]) / divisor,
            raw_obj["entropy"], raw_obj["paths"], raw_obj["urls"],
            raw_obj["registry"], raw_obj["MZ"],
        ]).astype(np.float32)


class GeneralFileInfo(FeatureType):
    name = "general"
    dim = 10

    def raw_features(self, bytez, lief_binary):
        if lief_binary is None:
            return {k: 0 for k in ("size", "vsize", "has_debug", "exports", "imports",
                                   "has_relocations", "has_resources", "has_signature",
                                   "has_tls", "symbols")} | {"size": len(bytez)}
        return {
            "size": len(bytez), "vsize": lief_binary.virtual_size,
            "has_debug": int(lief_binary.has_debug),
            "exports": len(lief_binary.exported_functions),
            "imports": len(lief_binary.imported_functions),
            "has_relocations": int(lief_binary.has_relocations),
            "has_resources": int(lief_binary.has_resources),
            "has_signature": int(lief_binary.has_signatures) if LIEF_HAS_SIGNATURE else int(lief_binary.has_signature),
            "has_tls": int(lief_binary.has_tls), "symbols": len(lief_binary.symbols),
        }

    def process_raw_features(self, raw_obj):
        return np.asarray([
            raw_obj["size"], raw_obj["vsize"], raw_obj["has_debug"],
            raw_obj["exports"], raw_obj["imports"], raw_obj["has_relocations"],
            raw_obj["has_resources"], raw_obj["has_signature"],
            raw_obj["has_tls"], raw_obj["symbols"],
        ], dtype=np.float32)


class HeaderFileInfo(FeatureType):
    name = "header"
    dim = 62

    def raw_features(self, bytez, lief_binary):
        raw = {
            "coff": {"timestamp": 0, "machine": "", "characteristics": []},
            "optional": {
                "subsystem": "", "dll_characteristics": [], "magic": "",
                "major_image_version": 0, "minor_image_version": 0,
                "major_linker_version": 0, "minor_linker_version": 0,
                "major_operating_system_version": 0, "minor_operating_system_version": 0,
                "major_subsystem_version": 0, "minor_subsystem_version": 0,
                "sizeof_code": 0, "sizeof_headers": 0, "sizeof_heap_commit": 0,
            },
        }
        if lief_binary is None:
            return raw
        raw["coff"]["timestamp"] = lief_binary.header.time_date_stamps
        raw["coff"]["machine"] = str(lief_binary.header.machine).split(".")[-1]
        raw["coff"]["characteristics"] = [str(c).split(".")[-1] for c in lief_binary.header.characteristics_list]
        opt = lief_binary.optional_header
        raw["optional"]["subsystem"] = str(opt.subsystem).split(".")[-1]
        raw["optional"]["dll_characteristics"] = [str(c).split(".")[-1] for c in opt.dll_characteristics_lists]
        raw["optional"]["magic"] = str(opt.magic).split(".")[-1]
        for k in ("major_image_version", "minor_image_version", "major_linker_version",
                  "minor_linker_version", "major_operating_system_version",
                  "minor_operating_system_version", "major_subsystem_version",
                  "minor_subsystem_version", "sizeof_code", "sizeof_headers",
                  "sizeof_heap_commit"):
            raw["optional"][k] = getattr(opt, k)
        return raw

    def process_raw_features(self, raw_obj):
        return np.hstack([
            raw_obj["coff"]["timestamp"],
            FeatureHasher(10, input_type="string").transform([[raw_obj["coff"]["machine"]]]).toarray()[0],
            FeatureHasher(10, input_type="string").transform([raw_obj["coff"]["characteristics"]]).toarray()[0],
            FeatureHasher(10, input_type="string").transform([[raw_obj["optional"]["subsystem"]]]).toarray()[0],
            FeatureHasher(10, input_type="string").transform([raw_obj["optional"]["dll_characteristics"]]).toarray()[0],
            FeatureHasher(10, input_type="string").transform([[raw_obj["optional"]["magic"]]]).toarray()[0],
            raw_obj["optional"]["major_image_version"], raw_obj["optional"]["minor_image_version"],
            raw_obj["optional"]["major_linker_version"], raw_obj["optional"]["minor_linker_version"],
            raw_obj["optional"]["major_operating_system_version"], raw_obj["optional"]["minor_operating_system_version"],
            raw_obj["optional"]["major_subsystem_version"], raw_obj["optional"]["minor_subsystem_version"],
            raw_obj["optional"]["sizeof_code"], raw_obj["optional"]["sizeof_headers"],
            raw_obj["optional"]["sizeof_heap_commit"],
        ]).astype(np.float32)


class SectionInfo(FeatureType):
    name = "section"
    dim = 255

    @staticmethod
    def _properties(s):
        return [str(c).split(".")[-1] for c in s.characteristics_lists]

    def raw_features(self, bytez, lief_binary):
        if lief_binary is None:
            return {"entry": "", "sections": []}
        try:
            if LIEF_MAJOR > 0 or (LIEF_MAJOR == 0 and LIEF_MINOR >= 12):
                section = lief_binary.section_from_rva(lief_binary.entrypoint - lief_binary.imagebase)
                if section is None:
                    raise lief.not_found
                entry_section = section.name
            else:
                entry_section = lief_binary.section_from_offset(lief_binary.entrypoint).name
        except Exception:
            entry_section = ""
            for s in lief_binary.sections:
                if lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE in s.characteristics_lists:
                    entry_section = s.name
                    break
        return {
            "entry": entry_section,
            "sections": [{
                "name": s.name, "size": s.size, "entropy": s.entropy,
                "vsize": s.virtual_size, "props": self._properties(s),
            } for s in lief_binary.sections],
        }

    def process_raw_features(self, raw_obj):
        sections = raw_obj["sections"]
        general = [
            len(sections),
            sum(1 for s in sections if s["size"] == 0),
            sum(1 for s in sections if s["name"] == ""),
            sum(1 for s in sections if "MEM_READ" in s["props"] and "MEM_EXECUTE" in s["props"]),
            sum(1 for s in sections if "MEM_WRITE" in s["props"]),
        ]
        sizes = FeatureHasher(50, input_type="pair").transform([[(s["name"], s["size"]) for s in sections]]).toarray()[0]
        entropy = FeatureHasher(50, input_type="pair").transform([[(s["name"], s["entropy"]) for s in sections]]).toarray()[0]
        vsize = FeatureHasher(50, input_type="pair").transform([[(s["name"], s["vsize"]) for s in sections]]).toarray()[0]
        entry_name = FeatureHasher(50, input_type="string").transform([[raw_obj["entry"]]]).toarray()[0]
        chars = [p for s in sections for p in s["props"] if s["name"] == raw_obj["entry"]]
        chars_hashed = FeatureHasher(50, input_type="string").transform([chars]).toarray()[0]
        return np.hstack([general, sizes, entropy, vsize, entry_name, chars_hashed]).astype(np.float32)


class ImportsInfo(FeatureType):
    name = "imports"
    dim = 1280

    def raw_features(self, bytez, lief_binary):
        imports = {}
        if lief_binary is None:
            return imports
        for lib in lief_binary.imports:
            imports.setdefault(lib.name, [])
            for entry in lib.entries:
                if entry.is_ordinal:
                    imports[lib.name].append("ordinal" + str(entry.ordinal))
                else:
                    imports[lib.name].append(entry.name[:10000])
        return imports

    def process_raw_features(self, raw_obj):
        libraries = list({l.lower() for l in raw_obj.keys()})
        libs_hashed = FeatureHasher(256, input_type="string").transform([libraries]).toarray()[0]
        imports = [lib.lower() + ":" + e for lib, elist in raw_obj.items() for e in elist]
        imports_hashed = FeatureHasher(1024, input_type="string").transform([imports]).toarray()[0]
        return np.hstack([libs_hashed, imports_hashed]).astype(np.float32)


class ExportsInfo(FeatureType):
    name = "exports"
    dim = 128

    def raw_features(self, bytez, lief_binary):
        if lief_binary is None:
            return []
        if LIEF_EXPORT_OBJECT:
            return [e.name[:10000] for e in lief_binary.exported_functions]
        return [e[:10000] for e in lief_binary.exported_functions]

    def process_raw_features(self, raw_obj):
        return FeatureHasher(128, input_type="string").transform([raw_obj]).toarray()[0].astype(np.float32)


class DataDirectories(FeatureType):
    name = "datadirectories"
    dim = 30

    def __init__(self):
        self._name_order = [
            "EXPORT_TABLE", "IMPORT_TABLE", "RESOURCE_TABLE", "EXCEPTION_TABLE",
            "CERTIFICATE_TABLE", "BASE_RELOCATION_TABLE", "DEBUG", "ARCHITECTURE",
            "GLOBAL_PTR", "TLS_TABLE", "LOAD_CONFIG_TABLE", "BOUND_IMPORT",
            "IAT", "DELAY_IMPORT_DESCRIPTOR", "CLR_RUNTIME_HEADER",
        ]

    def raw_features(self, bytez, lief_binary):
        if lief_binary is None:
            return []
        return [{
            "name": str(d.type).replace("DATA_DIRECTORY.", ""),
            "size": d.size, "virtual_address": d.rva,
        } for d in lief_binary.data_directories]

    def process_raw_features(self, raw_obj):
        features = np.zeros(2 * len(self._name_order), dtype=np.float32)
        for i in range(len(self._name_order)):
            if i < len(raw_obj):
                features[2 * i] = raw_obj[i]["size"]
                features[2 * i + 1] = raw_obj[i]["virtual_address"]
        return features


class PEFeatureExtractor:
    """Extract 2381 EMBER 2018 v2 features from PE file bytes."""

    def __init__(self, feature_version: int = 2):
        if not LIEF_AVAILABLE:
            raise ImportError("LIEF is required for PE feature extraction. Install with: pip install lief")
        if not SKLEARN_AVAILABLE:
            raise ImportError("scikit-learn is required for feature hashing.")
        self.features = [
            ByteHistogram(), ByteEntropyHistogram(), StringExtractor(),
            GeneralFileInfo(), HeaderFileInfo(), SectionInfo(),
            ImportsInfo(), ExportsInfo(),
        ]
        if feature_version == 2:
            self.features.append(DataDirectories())
        self.dim = sum(fe.dim for fe in self.features)

    def raw_features(self, bytez: bytes) -> Dict[str, Any]:
        try:
            lief_binary = lief.PE.parse(list(bytez))
        except Exception as exc:
            logger.warning("LIEF parsing error: %s", exc)
            lief_binary = None
        out = {"sha256": hashlib.sha256(bytez).hexdigest()}
        out.update({fe.name: fe.raw_features(bytez, lief_binary) for fe in self.features})
        return out

    def process_raw_features(self, raw_obj: Dict[str, Any]) -> np.ndarray:
        return np.hstack([fe.process_raw_features(raw_obj[fe.name]) for fe in self.features]).astype(np.float32)

    def feature_vector(self, bytez: bytes) -> np.ndarray:
        return self.process_raw_features(self.raw_features(bytez))

    def extract_with_hash(self, bytez: bytes) -> Tuple[np.ndarray, str]:
        raw = self.raw_features(bytez)
        return self.process_raw_features(raw), raw["sha256"]


_extractor: Optional[PEFeatureExtractor] = None


def get_feature_extractor() -> PEFeatureExtractor:
    global _extractor
    if _extractor is None:
        _extractor = PEFeatureExtractor()
    return _extractor
