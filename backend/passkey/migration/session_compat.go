package migration

import (
	"github.com/lestrrat-go/jwx/v2/jwt"
)

const (
	ClaimDeviceID   = "did"
	ClaimRelation   = "drel"
	ClaimTrustLevel = "trust_level"
	ClaimRecovered  = "passkey_recovered"
)

// ClaimMap returns optional device claims for the existing Hanko session JWT.
// Unknown claims are ignored by older consumers and by JWT verification, so
// sessions without these claims keep working.
func (c SessionClaims) ClaimMap() map[string]any {
	claims := make(map[string]any, 4)
	if c.DeviceID != "" {
		claims[ClaimDeviceID] = c.DeviceID
	}
	if c.Relation != "" {
		claims[ClaimRelation] = string(c.Relation)
	}
	if c.TrustLevel != "" {
		claims[ClaimTrustLevel] = c.TrustLevel
	}
	if c.Recovered {
		claims[ClaimRecovered] = true
	}
	return claims
}

// SessionClaimsFromToken extracts the optional device claims. Missing claims
// produce the zero value and therefore represent a legacy session.
func SessionClaimsFromToken(token jwt.Token) SessionClaims {
	claims := SessionClaims{}
	if token == nil {
		return claims
	}
	if value, ok := token.Get(ClaimDeviceID); ok {
		claims.DeviceID, _ = value.(string)
	}
	if value, ok := token.Get(ClaimRelation); ok {
		if relation, ok := value.(string); ok {
			claims.Relation = Relation(relation)
		}
	}
	if value, ok := token.Get(ClaimTrustLevel); ok {
		claims.TrustLevel, _ = value.(string)
	}
	if value, ok := token.Get(ClaimRecovered); ok {
		claims.Recovered, _ = value.(bool)
	}
	return claims
}
