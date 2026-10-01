"""Attacker-origin world map: per-country heat dots for Leaflet.

CENTROIDS below is generated (largest-ring bbox centers per ISO_A2 in
a 1000x500 equirectangular space); unproject() converts them back to
lat/lng, and dots() turns per-country attacker counts into sized,
colored markers for the dashboard Leaflet map.
"""
import math
from urllib.parse import quote

WIDTH, HEIGHT = 1000, 500

CARTO_KEY_SETTING = "carto.api_key"
_TILE_HOST = "https://{s}.basemaps.cartocdn.com"


def tile_url(style: str, api_key: str = "") -> str:
    """Leaflet tile URL for a CARTO basemap style.

    Since late Aug 2026 CARTO watermarks keyless tiles ("API KEY
    REQUIRED"), so a console key appends as ?api_key=; empty stays
    bare and degrades to watermarked tiles rather than failing.
    """
    url = f"{_TILE_HOST}/{style}/{{z}}/{{x}}/{{y}}{{r}}.png"
    if api_key and api_key.strip():
        url += f"?api_key={quote(api_key.strip(), safe='')}"
    return url

# Generated from ne_110m_admin_0_countries; do not hand-edit.
CENTROIDS = {
    "AE": (651, 183),
    "AF": (688, 153),
    "AL": (556, 135),
    "AM": (626, 139),
    "AO": (548, 280),
    "AQ": (37, 453),
    "AR": (319, 353),
    "AT": (537, 118),
    "AU": (870, 316),
    "AZ": (632, 138),
    "BA": (550, 127),
    "BD": (752, 185),
    "BE": (512, 109),
    "BF": (495, 216),
    "BG": (569, 131),
    "BI": (583, 259),
    "BJ": (506, 223),
    "BN": (819, 237),
    "BO": (322, 295),
    "BR": (342, 277),
    "BS": (283, 182),
    "BT": (752, 174),
    "BW": (568, 312),
    "BY": (579, 102),
    "BZ": (254, 202),
    "CA": (247, 93),
    "CD": (564, 261),
    "CF": (558, 233),
    "CG": (541, 253),
    "CH": (523, 120),
    "CI": (482, 228),
    "CL": (302, 356),
    "CM": (537, 231),
    "CN": (794, 146),
    "CO": (298, 238),
    "CR": (266, 223),
    "CU": (279, 190),
    "CY": (592, 153),
    "CZ": (544, 112),
    "DE": (530, 108),
    "DJ": (618, 217),
    "DK": (527, 94),
    "DO": (304, 198),
    "DZ": (508, 168),
    "EC": (281, 255),
    "EE": (573, 87),
    "EG": (588, 172),
    "EH": (467, 181),
    "ER": (610, 209),
    "ES": (488, 138),
    "ET": (609, 225),
    "FI": (572, 69),
    "FJ": (994, 299),
    "FK": (334, 394),
    "FR": (509, 119),
    "GA": (533, 251),
    "GB": (491, 100),
    "GE": (620, 133),
    "GH": (497, 227),
    "GL": (386, 44),
    "GM": (458, 212),
    "GN": (469, 221),
    "GQ": (528, 246),
    "GR": (564, 139),
    "GT": (249, 207),
    "GW": (458, 217),
    "GY": (336, 238),
    "HN": (260, 209),
    "HR": (546, 125),
    "HT": (298, 198),
    "HU": (553, 118),
    "ID": (781, 250),
    "IE": (479, 101),
    "IL": (598, 161),
    "IN": (732, 183),
    "IQ": (623, 157),
    "IR": (648, 157),
    "IS": (446, 69),
    "IT": (535, 130),
    "JM": (285, 199),
    "JO": (602, 164),
    "JP": (878, 151),
    "KE": (605, 247),
    "KG": (705, 135),
    "KH": (791, 215),
    "KP": (854, 139),
    "KR": (854, 148),
    "KW": (633, 169),
    "KZ": (681, 119),
    "LA": (788, 199),
    "LB": (600, 156),
    "LK": (725, 229),
    "LR": (475, 231),
    "LS": (579, 332),
    "LT": (567, 97),
    "LU": (517, 112),
    "LV": (569, 92),
    "LY": (546, 171),
    "MA": (474, 170),
    "MD": (579, 119),
    "ME": (554, 131),
    "MG": (631, 300),
    "MK": (560, 134),
    "ML": (484, 211),
    "MM": (770, 194),
    "MN": (791, 119),
    "MR": (465, 198),
    "MW": (595, 286),
    "MX": (214, 184),
    "MY": (819, 240),
    "MZ": (597, 299),
    "NA": (550, 310),
    "NC": (960, 309),
    "NE": (524, 207),
    "NG": (523, 223),
    "NI": (264, 214),
    "NL": (515, 105),
    "NO": (550, 66),
    "NP": (735, 172),
    "NZ": (975, 371),
    "OM": (657, 192),
    "PA": (277, 226),
    "PE": (294, 272),
    "PG": (906, 272),
    "PH": (838, 207),
    "PK": (693, 164),
    "PL": (554, 106),
    "PR": (315, 199),
    "PS": (598, 162),
    "PT": (478, 140),
    "PY": (340, 315),
    "QA": (642, 180),
    "RO": (570, 123),
    "RS": (558, 128),
    "RU": (752, 86),
    "RW": (583, 256),
    "SA": (621, 183),
    "SB": (942, 272),
    "SD": (581, 214),
    "SE": (546, 76),
    "SI": (542, 122),
    "SK": (554, 115),
    "SL": (467, 226),
    "SN": (459, 211),
    "SO": (630, 232),
    "SR": (345, 240),
    "SS": (584, 228),
    "SV": (253, 212),
    "SY": (605, 152),
    "SZ": (587, 323),
    "TD": (550, 214),
    "TF": (693, 386),
    "TG": (502, 225),
    "TH": (780, 213),
    "TJ": (697, 143),
    "TL": (850, 274),
    "TM": (662, 141),
    "TN": (527, 156),
    "TR": (603, 143),
    "TT": (329, 221),
    "TZ": (595, 268),
    "UA": (585, 115),
    "UG": (589, 246),
    "US": (249, 144),
    "UY": (344, 341),
    "UZ": (681, 136),
    "VE": (314, 230),
    "VN": (794, 204),
    "VU": (964, 293),
    "YE": (629, 207),
    "ZA": (569, 329),
    "ZM": (578, 286),
    "ZW": (582, 302),
}


def project(lon: float, lat: float) -> tuple:
    """Equirectangular lon/lat to integer map space (1000x500)."""
    return (int(round((lon + 180.0) / 360.0 * WIDTH)),
            int(round((90.0 - lat) / 180.0 * HEIGHT)))


def unproject(x: int, y: int) -> tuple:
    """Integer map space back to (lat, lon); inverse of project()."""
    return (round(90.0 - y / HEIGHT * 180.0, 4),
            round(x / WIDTH * 360.0 - 180.0, 4))


def dot_radius(attackers: int) -> int:
    """Circle radius grows with the square root of attacker count."""
    return min(16, 4 + int(round(3 * math.sqrt(max(attackers, 1)))))


def heat_color(attackers: int) -> str:
    """Marker color by heat: amber for trickles, red for floods."""
    return "#dc2626" if attackers >= 10 else "#d97706"


def heat_opacity(attackers: int) -> float:
    """Marker fill opacity: faint singletons, solid crowds."""
    return 0.65 if attackers >= 3 else 0.4


def dots(rows) -> tuple:
    """Map-ready dots + unplottable count from attacker_geo() rows.

    Rows are (country_code, country, attackers, sessions); unknown or
    unmapped codes collapse into the second return value. Dots come
    out ascending by heat so the hottest render on top.
    """
    out, unknown = [], 0
    for code, country, attackers, sessions in rows:
        center = CENTROIDS.get((code or "").upper())
        if center is None:
            unknown += attackers
            continue
        lat, lon = unproject(*center)
        label = f"{country or code} ({code}): {attackers} attacker" \
            f"{'s' if attackers != 1 else ''}, {sessions} session" \
            f"{'s' if sessions != 1 else ''}"
        out.append({"lat": lat, "lon": lon, "r": dot_radius(attackers),
                    "color": heat_color(attackers),
                    "opacity": heat_opacity(attackers), "label": label,
                    "attackers": attackers})
    out.sort(key=lambda d: d["attackers"])
    return out, unknown
