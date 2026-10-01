"""World-map helpers: projection, heat scaling, centroid sanity."""
import unittest

from carbide.server.web.geomap import (CENTROIDS, HEIGHT, WIDTH,
                                       dot_radius, dots, heat_color,
                                       heat_opacity, project, tile_url,
                                       unproject)


class GeomapTest(unittest.TestCase):
    def test_projection_corners(self):
        self.assertEqual(project(-180, 90), (0, 0))
        self.assertEqual(project(180, -90), (WIDTH, HEIGHT))
        self.assertEqual(project(0, 0), (WIDTH // 2, HEIGHT // 2))

    def test_unproject_inverts_projection(self):
        self.assertEqual(unproject(0, 0), (90.0, -180.0))
        self.assertEqual(unproject(WIDTH, HEIGHT), (-90.0, 180.0))
        self.assertEqual(unproject(WIDTH // 2, HEIGHT // 2), (0.0, 0.0))
        lat, lon = unproject(*CENTROIDS["NL"])
        self.assertAlmostEqual(lat, 52.2)
        self.assertAlmostEqual(lon, 5.4)
        for code in ("NL", "US", "AU", "BR", "JP", "ZA"):
            x, y = CENTROIDS[code]
            lat, lon = unproject(x, y)
            px, py = project(lon, lat)
            self.assertLessEqual(abs(px - x), 1, code)
            self.assertLessEqual(abs(py - y), 1, code)

    def test_dot_radius_scales_and_caps(self):
        self.assertEqual(dot_radius(1), 7)
        self.assertLess(dot_radius(1), dot_radius(4))
        self.assertLess(dot_radius(4), dot_radius(25))
        self.assertEqual(dot_radius(10**6), 16)

    def test_heat_colors_and_opacity(self):
        self.assertEqual(heat_color(1), "#d97706")
        self.assertEqual(heat_color(3), "#d97706")
        self.assertEqual(heat_color(10), "#dc2626")
        self.assertEqual(heat_opacity(1), 0.4)
        self.assertEqual(heat_opacity(3), 0.65)
        self.assertEqual(heat_opacity(10), 0.65)

    def test_dots_map_and_sort(self):
        out, unknown = dots([
            ("NL", "Netherlands", 2, 5),
            ("XX", "Nowhere", 4, 4),
            ("US", "United States", 12, 30),
        ])
        self.assertEqual(unknown, 4)
        self.assertEqual([(d["lat"], d["lon"]) for d in out],
                         [unproject(*CENTROIDS["NL"]),
                          unproject(*CENTROIDS["US"])])
        self.assertIn("Netherlands (NL): 2 attackers, 5 sessions",
                      out[0]["label"])
        self.assertEqual(out[0]["r"], dot_radius(2))
        self.assertEqual(out[0]["color"], "#d97706")
        self.assertEqual(out[1]["color"], "#dc2626")

    def test_tile_url(self):
        self.assertEqual(
            tile_url("light_all"),
            "https://{s}.basemaps.cartocdn.com/light_all/"
            "{z}/{x}/{y}{r}.png")
        self.assertEqual(
            tile_url("dark_all", "secret-key-1"),
            "https://{s}.basemaps.cartocdn.com/dark_all/"
            "{z}/{x}/{y}{r}.png?api_key=secret-key-1")
        # blank stays bare; reserved chars are quoted
        self.assertEqual(tile_url("light_all", "  "),
                         tile_url("light_all"))
        self.assertIn("api_key=a%2Fb%3Fc",
                      tile_url("light_all", "a/b?c"))

    def test_centroid_sanity(self):
        self.assertGreater(len(CENTROIDS), 150)
        for code, (x, y) in CENTROIDS.items():
            self.assertEqual(len(code), 2, code)
            self.assertTrue(0 <= x <= WIDTH, code)
            self.assertTrue(0 <= y <= HEIGHT, code)
        # Spot checks land on the right continents.
        self.assertEqual(CENTROIDS["NL"], (515, 105))
        self.assertEqual(CENTROIDS["US"], (249, 144))
        self.assertEqual(CENTROIDS["AU"], (870, 316))
        self.assertEqual(CENTROIDS["BR"], (342, 277))
