package nft

import (
//	"fmt"
)

type Chain struct {
	Name string
}

// Get all rules for given chain
func (c *Chain) GetRules() ([]Rule, error) {
	rules := getRules(c.Name, "ip")

	return rulesConvert(rules)
}
