package firewall

import (
	"fmt"

	"github.com/netxops/utils/policy"
)

func PrintDebug(oneName string, onePolicyEntry policy.PolicyEntryInf, twoName string, twoPolicyEntry policy.PolicyEntryInf) {
	fmt.Printf("[DEBUG] %s: %s\n", oneName, onePolicyEntry.String())
	fmt.Printf("[DEBUG] %s: %s\n", twoName, twoPolicyEntry.String())
}
