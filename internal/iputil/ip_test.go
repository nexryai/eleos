package iputil

import (
	"testing"
)

func testIPAddressExtracer(t *testing.T, testIP string, expectedResult string) {
	result, err := ExtractIPAddress(testIP)
	if err != nil {
		if expectedResult != "ERROR" {
			t.Errorf("function returned an error")
		} else if err != nil && expectedResult == "ERROR" {
			return
		}
	}
	if result != expectedResult {
		t.Errorf("ExtractIPAddress(%s) = %s, expected %s", testIP, result, expectedResult)
	}
}

func TestExtractIPAddress(t *testing.T) {
	testIPAddressExtracer(t, "192.168.1.1:22", "192.168.1.1")
	testIPAddressExtracer(t, "192.168.999.888:5432", "ERROR")
	testIPAddressExtracer(t, "0.0.0.0:9999", "0.0.0.0")
	testIPAddressExtracer(t, "255.255.255.255:2", "255.255.255.255")
}

// isValidIPのテスト
func TestIsValidIP(t *testing.T) {
	validIP := "192.168.1.1"
	invalidIP := "invalidIP"

	if !isValidIP(validIP) {
		t.Errorf("Expected %s to be a valid IP address, but it is not.", validIP)
	}

	if isValidIP(invalidIP) {
		t.Errorf("Expected %s to be an invalid IP address, but it is valid.", invalidIP)
	}
}

// CheckIPAddressesのテスト
func TestCheckIPAddresses(t *testing.T) {
	validIPs := []string{"192.168.1.1", "10.0.0.1"}
	invalidIPs := []string{"192.168.1.1", "invalidIP"}

	if !CheckIPAddresses(validIPs) {
		t.Error("Expected all IP addresses to be valid, but some are not.")
	}

	if CheckIPAddresses(invalidIPs) {
		t.Error("Expected some IP addresses to be invalid, but all are valid.")
	}
}

// IsIPv6のテスト
func TestIsIPv6(t *testing.T) {
	ipv6Address := "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
	ipv4Address := "192.168.1.1"

	if !IsIPv6(ipv6Address) {
		t.Errorf("Expected %s to be an IPv6 address, but it is not.", ipv6Address)
	}

	if IsIPv6(ipv4Address) {
		t.Errorf("Expected %s not to be an IPv6 address, but it is.", ipv4Address)
	}
}
