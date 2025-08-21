from typing import Dict, Optional

try:
    import geoip2.database
except Exception:
    geoip2 = None 


class GeoIPEnricher:
    """
    Optional GeoIP enricher. Pass path to MaxMind GeoLite2-City.mmdb.
    If not available, enrichment returns {}.
    """

    def __init__(self, mmdb_path: Optional[str] = None):
        self.mmdb_path = mmdb_path
        self.reader = None
        if mmdb_path and geoip2 is not None:
            try:
                self.reader = geoip2.database.Reader(mmdb_path)
            except Exception:
                self.reader = None

    def lookup(self, ip: str) -> Dict[str, str]:
        if not self.reader:
            return {}
        try:
            resp = self.reader.city(ip)
            return {
                "geo_country": (resp.country.iso_code or ""),
                "geo_city": (resp.city.name or ""),
                "geo_asn": "",
            }
        except Exception:
            return {}

    def close(self):
        try:
            if self.reader:
                self.reader.close()
        except Exception:
            pass
