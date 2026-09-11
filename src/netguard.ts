import { lookup } from "node:dns/promises";
import type { LookupAddress } from "node:dns";
import ipaddr from "ipaddr.js";

import { BlindDropError } from "./errors.js";

// Adapted from Infisical Agent Vault's validated-address dial guard:
// internal/netguard/netguard.go at
// bd1a325d79129644487f3e5b4f18c51adbc64638. BlindDrop resolves every address,
// checks the complete result, and later gives Node HTTPS one checked address so
// the socket cannot trigger a second hostname lookup.
const ALWAYS_BLOCKED = [
  ipaddr.parseCIDR("169.254.169.254/32"),
  ipaddr.parseCIDR("fd00:ec2::254/128"),
  // Google Compute Engine metadata endpoint:
  // https://docs.cloud.google.com/compute/docs/metadata/overview
  ipaddr.parseCIDR("fd20:ce::254/128"),
  // Alibaba Cloud ECS metadata endpoint:
  // https://www.alibabacloud.com/help/en/ecs/user-guide/view-instance-metadata/
  ipaddr.parseCIDR("100.100.100.200/32"),
];

export interface ValidatedAddress {
  address: string;
  family: 4 | 6;
}

function parseAddress(address: string): ipaddr.IPv4 | ipaddr.IPv6 {
  try {
    return ipaddr.process(address);
  } catch {
    throw new BlindDropError("DESTINATION_DENIED");
  }
}

export function isAddressPermitted(address: string, allowPrivate: boolean): boolean {
  let parsed: ipaddr.IPv4 | ipaddr.IPv6;
  try {
    parsed = parseAddress(address);
  } catch {
    return false;
  }

  const rangeName = parsed.range();
  if (
    rangeName === "unspecified" ||
    ALWAYS_BLOCKED.some(
      (range) => parsed.kind() === range[0].kind() && parsed.match(range),
    )
  ) {
    return false;
  }

  return allowPrivate || rangeName === "unicast";
}

/**
 * Validate a resolver result and choose the address that HTTPS will dial.
 * Exported as the narrow resolver test boundary; Broker callers cannot supply
 * this list and always use resolveValidatedAddress below.
 */
export function selectValidatedAddress(
  addresses: readonly LookupAddress[],
  allowPrivate: boolean,
): ValidatedAddress {
  if (addresses.length === 0) {
    throw new BlindDropError("DESTINATION_DENIED");
  }

  for (const candidate of addresses) {
    if (
      (candidate.family !== 4 && candidate.family !== 6) ||
      !isAddressPermitted(candidate.address, allowPrivate)
    ) {
      throw new BlindDropError("DESTINATION_DENIED");
    }
  }

  const selected = addresses[0];
  return { address: selected.address, family: selected.family as 4 | 6 };
}

export async function resolveValidatedAddress(
  hostname: string,
  allowPrivate: boolean,
): Promise<ValidatedAddress> {
  const lookupName = hostname.startsWith("[") && hostname.endsWith("]")
    ? hostname.slice(1, -1)
    : hostname;

  try {
    const addresses = await lookup(lookupName, { all: true, order: "verbatim" });
    return selectValidatedAddress(addresses, allowPrivate);
  } catch (error) {
    if (error instanceof BlindDropError) {
      throw error;
    }
    throw new BlindDropError("DESTINATION_DENIED");
  }
}
