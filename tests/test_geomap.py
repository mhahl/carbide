"""World-map helpers: projection, heat scaling, centroid sanity."""
import unittest

from carbide.server.web.geomap import (CENTROIDS, HEIGHT, WIDTH,
                                       dot_radius, dots, heat_class,
                                       project)


class GeomapTest(unittest.TestCase):
    def test_projection_corners(self):
        self.assertEqual(project(-180, 90), (0, 0))
        self.assertEqual(project(180, -90), (WIDTH, HEIGHT))
        self.assertEqual(project(0, 0), (WIDTH // 2, HEIGHT // 2))

    def test_dot_radius_scales_and_caps(self):
        self.assertEqual(dot_radius(1), 7)
        self.assertLess(dot_radius(1), dot_radius(4))
        self.assertLess(dot_radius(4), dot_radius(25))
        self.assertEqual(dot_radius(10**6), 16)

    def test_heat_classes(self):
        self.assertEqual(heat_class(1), "fill-warning opacity-60")
        self.assertEqual(heat_class(3), "fill-warning")
        self.assertEqual(heat_class(10), "fill-error")

    def test_dots_map_and_sort(self):
        out, unknown = dots([
            ("NL", "Netherlands", 2, 5),
            ("XX", "Nowhere", 4, 4),
            ("US", "United States", 12, 30),
        ])
        self.assertEqual(unknown, 4)
        self.assertEqual([(d["x"], d["y"]) for d in out],
                         [CENTROIDS["NL"], CENTROIDS["US"]])
        self.assertIn("Netherlands (NL): 2 attackers, 5 sessions",
                      out[0]["label"])
        self.assertEqual(out[1]["class"], "fill-error")

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
