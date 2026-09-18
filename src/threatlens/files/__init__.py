"""File detection: PE/EMBER feature extraction and the malware classifier."""

from .detector import PEDetector
from .ember_features import PEFeatureExtractor, get_feature_extractor

__all__ = ["PEDetector", "PEFeatureExtractor", "get_feature_extractor"]
