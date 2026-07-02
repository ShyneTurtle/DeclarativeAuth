package auth

import (
	"fmt"
	"math"
)

// PasswordPolicy sets the minimum requirements a new password must meet.
// It's enforced wherever a password is set by a human (currently the
// password reset / first-password-setup web flow); the `admin set-password`
// CLI escape hatch deliberately bypasses it, since that command exists for
// bootstrap/testing use.
type PasswordPolicy struct {
	MinLength   int // Minimum character count. 0 falls back to 8.
	MinStrength int // Minimum Strength() score required, 0-4. 0 falls back to 2 ("fair").
}

// Validate returns a human-readable error describing why password doesn't
// meet the policy, or nil if it does.
func (p PasswordPolicy) Validate(password string) error {
	minLength := p.MinLength
	if minLength == 0 {
		minLength = 8
	}
	if len(password) < minLength {
		return fmt.Errorf("password must be at least %d characters", minLength)
	}
	minStrength := p.MinStrength
	if minStrength == 0 {
		minStrength = 2
	}
	if score := Strength(password); score < minStrength {
		return fmt.Errorf("password is too weak (%s) -- %s or stronger is required", StrengthLabel(score), StrengthLabel(minStrength))
	}
	return nil
}

// Strength scores a password from 0 (very weak) to 4 (strong) by estimating
// its entropy under the CHEAPEST attack an attacker would actually try
// (see passwordBits), chosen so the client-side live indicator
// (internal/web/static/strength.js) can mirror it exactly in a few dozen
// lines of vanilla JS without vendoring a scoring library.
//
// Keep the two implementations in sync if either changes -- the indicator
// must never promise a password will be accepted when the server would
// actually reject it.
func Strength(password string) int {
	bits := passwordBits(password)
	switch {
	case bits < 28:
		return 0
	case bits < 36:
		return 1
	case bits < 60:
		return 2
	case bits < 80:
		return 3
	default:
		return 4
	}
}

// StrengthLabel returns a short human-readable label for a Strength() score.
func StrengthLabel(score int) string {
	switch score {
	case 0:
		return "very weak"
	case 1:
		return "weak"
	case 2:
		return "fair"
	case 3:
		return "good"
	default:
		return "strong"
	}
}

// sequenceGuessBits estimates the cost of guessing a run of sequential
// characters (e.g. "1234", "abcd", "9876"): roughly log2(2 directions * ~32
// plausible starting points in a mixed alphabet) -- a small, deliberately
// rough constant, not a rigorous bound.
const sequenceGuessBits = 6.0

// minSequenceRun is the shortest sequential run treated as a pattern.
// 4 (not zxcvbn's usual 3) so incidental 3-character runs inside an
// otherwise-random password (e.g. the "123" in "Secret123!") aren't
// penalized -- the goal is to catch "1234"/"abcd"-style passwords, not
// dock points for coincidence.
const minSequenceRun = 4

// passwordBits estimates a password's real guessing difficulty by taking
// the MINIMUM of several attack strategies -- i.e. however an attacker
// would actually crack it fastest is what determines the "strength":
//
//  1. Brute force: length * log2(poolSize), the naive per-character estimate.
//  2. Repetition: if the password is just a short unit repeated (e.g.
//     "1234" x5, "ababab", "aaaaaaaa"), an attacker only needs to guess the
//     unit and how many times it repeats -- overwhelmingly cheaper than
//     brute-forcing the full length once the unit is short.
//  3. Sequences: a run of consecutive ascending/descending characters
//     (e.g. "1234", "abcd") costs a small constant to guess, not one full
//     character's worth of entropy per position.
//
// This is still a coarse heuristic (no dictionary of common
// words/passwords), but it's enough to stop "1234" repeated a few times
// from scoring as "strong", which pure brute-force length scoring did.
func passwordBits(password string) float64 {
	rs := []rune(password)
	if len(rs) == 0 {
		return 0
	}
	pool := charPool(rs)
	if pool == 0 {
		return 0
	}
	bits := float64(len(rs)) * math.Log2(float64(pool))

	if unit, count := detectRepeat(rs); count >= 2 {
		if unitPool := charPool(unit); unitPool > 0 {
			candidate := float64(len(unit))*math.Log2(float64(unitPool)) + math.Log2(float64(count))
			bits = math.Min(bits, candidate)
		}
	}

	if run := longestSequenceRun(rs); run >= minSequenceRun {
		candidate := float64(len(rs)-run)*math.Log2(float64(pool)) + sequenceGuessBits
		bits = math.Min(bits, candidate)
	}

	return bits
}

// charPool sums the alphabet sizes of the character classes present in rs:
// lowercase (26), uppercase (26), digit (10), and "everything else" (33,
// covering common ASCII symbols). It's an upper bound, not exact -- good
// enough for a coarse strength estimate.
func charPool(rs []rune) int {
	var pool int
	var hasLower, hasUpper, hasDigit, hasSymbol bool
	for _, r := range rs {
		switch {
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= '0' && r <= '9':
			hasDigit = true
		default:
			hasSymbol = true
		}
	}
	if hasLower {
		pool += 26
	}
	if hasUpper {
		pool += 26
	}
	if hasDigit {
		pool += 10
	}
	if hasSymbol {
		pool += 33
	}
	return pool
}

// detectRepeat finds the shortest unit whose repetition exactly tiles rs
// (e.g. "abab" -> unit "ab", count 2; "aaaa" -> unit "a", count 4). Returns
// count 0 if rs isn't an exact repetition of any unit shorter than itself.
func detectRepeat(rs []rune) (unit []rune, count int) {
	n := len(rs)
	for p := 1; p <= n/2; p++ {
		if n%p != 0 {
			continue
		}
		tiles := true
		for i := p; i < n; i++ {
			if rs[i] != rs[i-p] {
				tiles = false
				break
			}
		}
		if tiles {
			return rs[:p], n / p
		}
	}
	return nil, 0
}

// longestSequenceRun returns the length of the longest run of consecutive
// ascending or descending codepoints in rs (letters compared
// case-insensitively), e.g. 4 for "1234", "abcd", or "dcba".
func longestSequenceRun(rs []rune) int {
	if len(rs) == 0 {
		return 0
	}
	best, cur, dir := 1, 1, 0
	for i := 1; i < len(rs); i++ {
		d := int(normalizeRune(rs[i])) - int(normalizeRune(rs[i-1]))
		if d == 1 || d == -1 {
			if cur > 1 && d != dir {
				cur = 2
			} else {
				cur++
			}
			dir = d
		} else {
			cur = 1
			dir = 0
		}
		if cur > best {
			best = cur
		}
	}
	return best
}

func normalizeRune(r rune) rune {
	if r >= 'A' && r <= 'Z' {
		return r - 'A' + 'a'
	}
	return r
}
