package classify

import "math"

// ScoreStage2 computes a heuristic threat score from Stage 1 matches. The
// score accounts for pattern severity weights, match density, spatial
// clustering, encoding presence, and dangerous category proximity.
func (e *Engine) ScoreStage2(matches []Match, textLen int, hasEncoded bool) float64 {
	if len(matches) == 0 {
		return 0
	}

	// Build weight slice from pattern definitions.
	weights := make([]float64, len(matches))
	for i, m := range matches {
		weights[i] = e.weightForPattern(m.PatternID)
	}

	// Proximity bonus: authority-claim + instruction-override within 200 chars.
	applyProximityBonus(matches, weights, "authority-claim", "instruction-override", 200, 1.5)

	// Clustering: any two matches within 200 chars of each other get a 1.5x boost.
	applyClusteringBonus(matches, weights, 200, 1.5)

	// Base score: sum of (possibly boosted) weights.
	total := 0.0
	for _, w := range weights {
		total += w
	}

	// Density factor: if more than 2 matches per 1000 chars, boost by 1.2x.
	if textLen > 0 {
		density := float64(len(matches)) / (float64(textLen) / 1000.0)
		if density > 2.0 {
			total *= 1.2
		}
	}

	// Encoding penalty: content contained encoded payloads.
	if hasEncoded {
		total *= 1.3
	}

	// Round to 4 decimal places.
	return math.Round(total*10000) / 10000
}

// weightForPattern looks up the scoring weight for a pattern by ID.
func (e *Engine) weightForPattern(id string) float64 {
	for _, p := range e.patterns.allDefinitions {
		if p.ID == id {
			return p.Weight
		}
	}
	return 1.0
}

// applyProximityBonus multiplies weights by the given factor when matches
// from the two specified categories appear within maxDist characters of each
// other.
func applyProximityBonus(matches []Match, weights []float64, catA, catB string, maxDist int, factor float64) {
	for i, mi := range matches {
		for j, mj := range matches {
			if i == j {
				continue
			}
			if (mi.Category == catA && mj.Category == catB) ||
				(mi.Category == catB && mj.Category == catA) {
				dist := mi.Offset - mj.Offset
				if dist < 0 {
					dist = -dist
				}
				if dist <= maxDist {
					weights[i] *= factor
					weights[j] *= factor
				}
			}
		}
	}
}

// applyClusteringBonus boosts weights when any two matches are within maxDist
// characters of each other.
func applyClusteringBonus(matches []Match, weights []float64, maxDist int, factor float64) {
	boosted := make([]bool, len(matches))

	for i := range matches {
		for j := i + 1; j < len(matches); j++ {
			dist := matches[i].Offset - matches[j].Offset
			if dist < 0 {
				dist = -dist
			}
			if dist <= maxDist {
				if !boosted[i] {
					weights[i] *= factor
					boosted[i] = true
				}
				if !boosted[j] {
					weights[j] *= factor
					boosted[j] = true
				}
			}
		}
	}
}
