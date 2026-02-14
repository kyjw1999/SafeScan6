import re
from urllib.parse import urlparse

def extract_url_features(url):
    parsed = urlparse(url)

    return [
        len(url),
        int(parsed.scheme == "https"),
        url.count("."),
        url.count("-"),
        url.count("@"),
        url.count("/"),
        int(bool(re.search(r"\d+\.\d+\.\d+\.\d+", url)))
    ]