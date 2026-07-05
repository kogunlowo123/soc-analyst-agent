"""Internal API tools -- CMDB, Active Directory, network topology, vuln scanners.

These tools query the organisation's internal systems to provide
investigation context for SOC analysts.  Every function returns
structured data.
"""

from __future__ import annotations

import os
from typing import Any

import httpx
import structlog
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

logger = structlog.get_logger(__name__)

_RETRY = retry(
    retry=retry_if_exception_type((httpx.TimeoutException, httpx.ConnectError)),
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=8),
    reraise=True,
)


# ---------------------------------------------------------------------------
# Asset / CMDB lookup
# ---------------------------------------------------------------------------

async def lookup_asset(hostname_or_ip: str) -> dict[str, Any]:
    """Query the CMDB / asset inventory for a host.

    Environment:
        CMDB_BASE_URL  -- e.g. https://cmdb.corp.local/api/v1
        CMDB_API_KEY
    """
    base_url = os.environ.get("CMDB_BASE_URL", "https://localhost/api/v1")
    api_key = os.environ.get("CMDB_API_KEY", "")

    logger.info("lookup_asset_start", identifier=hostname_or_ip)

    @_RETRY
    async def _dispatch() -> dict[str, Any]:
        async with httpx.AsyncClient(
            base_url=base_url,
            headers={"Authorization": f"Bearer {api_key}", "Accept": "application/json"},
            timeout=15,
        ) as c:
            resp = await c.get(
                "/assets/search",
                params={"q": hostname_or_ip},
            )
            resp.raise_for_status()
            data = resp.json()
            assets = data.get("results", data.get("assets", []))

            if not assets:
                return {
                    "identifier": hostname_or_ip,
                    "found": False,
                    "asset": None,
                }

            asset = assets[0]
            return {
                "identifier": hostname_or_ip,
                "found": True,
                "asset": {
                    "hostname": asset.get("hostname"),
                    "ip_addresses": asset.get("ip_addresses", []),
                    "os": asset.get("operating_system"),
                    "os_version": asset.get("os_version"),
                    "owner": asset.get("owner"),
                    "department": asset.get("department"),
                    "location": asset.get("location"),
                    "asset_type": asset.get("asset_type"),
                    "criticality": asset.get("criticality", "medium"),
                    "last_seen": asset.get("last_seen"),
                    "installed_software": asset.get("installed_software", []),
                    "tags": asset.get("tags", []),
                },
            }

    try:
        return await _dispatch()
    except Exception as exc:
        logger.warning("lookup_asset_failed", identifier=hostname_or_ip, error=str(exc))
        return {
            "identifier": hostname_or_ip,
            "found": False,
            "asset": None,
            "error": str(exc),
        }


# ---------------------------------------------------------------------------
# User / Active Directory lookup
# ---------------------------------------------------------------------------

async def lookup_user(username_or_email: str) -> dict[str, Any]:
    """Query Active Directory / HR system for user details.

    Environment:
        AD_GRAPH_BASE_URL  -- Microsoft Graph base (default: https://graph.microsoft.com/v1.0)
        AD_GRAPH_TOKEN     -- Bearer token
    """
    graph_url = os.environ.get("AD_GRAPH_BASE_URL", "https://graph.microsoft.com/v1.0")
    token = os.environ.get("AD_GRAPH_TOKEN", "")

    logger.info("lookup_user_start", identifier=username_or_email)

    if not token:
        return {
            "identifier": username_or_email,
            "found": False,
            "user": None,
            "error": "AD_GRAPH_TOKEN not configured",
        }

    @_RETRY
    async def _dispatch() -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=15) as c:
            # Try exact UPN first, then fall back to search
            resp = await c.get(
                f"{graph_url}/users/{username_or_email}",
                headers={"Authorization": f"Bearer {token}"},
                params={
                    "$select": (
                        "id,displayName,mail,userPrincipalName,"
                        "jobTitle,department,officeLocation,"
                        "accountEnabled,createdDateTime,lastSignInDateTime"
                    )
                },
            )

            if resp.status_code == 404:
                # Fall back to search
                search_resp = await c.get(
                    f"{graph_url}/users",
                    headers={"Authorization": f"Bearer {token}"},
                    params={
                        "$filter": (
                            f"startswith(userPrincipalName,'{username_or_email}') "
                            f"or startswith(mail,'{username_or_email}')"
                        ),
                        "$top": "1",
                    },
                )
                search_resp.raise_for_status()
                users = search_resp.json().get("value", [])
                if not users:
                    return {"identifier": username_or_email, "found": False, "user": None}
                user_data = users[0]
            else:
                resp.raise_for_status()
                user_data = resp.json()

            # Fetch group memberships
            groups_resp = await c.get(
                f"{graph_url}/users/{user_data['id']}/memberOf",
                headers={"Authorization": f"Bearer {token}"},
                params={"$select": "displayName,id", "$top": "50"},
            )
            groups: list[str] = []
            if groups_resp.status_code == 200:
                groups = [
                    g.get("displayName", "")
                    for g in groups_resp.json().get("value", [])
                    if g.get("displayName")
                ]

            return {
                "identifier": username_or_email,
                "found": True,
                "user": {
                    "id": user_data.get("id"),
                    "display_name": user_data.get("displayName"),
                    "email": user_data.get("mail"),
                    "upn": user_data.get("userPrincipalName"),
                    "job_title": user_data.get("jobTitle"),
                    "department": user_data.get("department"),
                    "office_location": user_data.get("officeLocation"),
                    "account_enabled": user_data.get("accountEnabled"),
                    "created": user_data.get("createdDateTime"),
                    "last_sign_in": user_data.get("lastSignInDateTime"),
                    "groups": groups,
                },
            }

    try:
        return await _dispatch()
    except Exception as exc:
        logger.warning("lookup_user_failed", identifier=username_or_email, error=str(exc))
        return {
            "identifier": username_or_email,
            "found": False,
            "user": None,
            "error": str(exc),
        }


# ---------------------------------------------------------------------------
# Network topology
# ---------------------------------------------------------------------------

async def get_network_topology(subnet: str) -> dict[str, Any]:
    """Query the network management system for subnet topology.

    Environment:
        NETMGMT_BASE_URL  -- e.g. https://netbox.corp.local/api
        NETMGMT_API_KEY
    """
    base_url = os.environ.get("NETMGMT_BASE_URL", "https://localhost/api")
    api_key = os.environ.get("NETMGMT_API_KEY", "")

    logger.info("get_network_topology_start", subnet=subnet)

    @_RETRY
    async def _dispatch() -> dict[str, Any]:
        async with httpx.AsyncClient(
            base_url=base_url,
            headers={"Authorization": f"Token {api_key}", "Accept": "application/json"},
            timeout=15,
        ) as c:
            # Query prefixes for the subnet
            prefix_resp = await c.get("/ipam/prefixes/", params={"prefix": subnet})
            prefix_resp.raise_for_status()
            prefixes = prefix_resp.json().get("results", [])

            # Query IP addresses within the subnet
            ip_resp = await c.get("/ipam/ip-addresses/", params={"parent": subnet, "limit": 200})
            ip_resp.raise_for_status()
            ip_addresses = ip_resp.json().get("results", [])

            # Query VLANs associated
            vlan_resp = await c.get("/ipam/vlans/", params={"q": subnet})
            vlan_resp.raise_for_status()
            vlans = vlan_resp.json().get("results", [])

            return {
                "subnet": subnet,
                "found": len(prefixes) > 0,
                "topology": {
                    "prefix": prefixes[0] if prefixes else None,
                    "total_ips": len(ip_addresses),
                    "ip_addresses": [
                        {
                            "address": ip.get("address"),
                            "status": ip.get("status", {}).get("value"),
                            "dns_name": ip.get("dns_name"),
                            "assigned_object": ip.get("assigned_object_type"),
                        }
                        for ip in ip_addresses[:50]
                    ],
                    "vlans": [
                        {"id": v.get("vid"), "name": v.get("name"), "status": v.get("status", {}).get("value")}
                        for v in vlans
                    ],
                },
            }

    try:
        return await _dispatch()
    except Exception as exc:
        logger.warning("get_network_topology_failed", subnet=subnet, error=str(exc))
        return {
            "subnet": subnet,
            "found": False,
            "topology": None,
            "error": str(exc),
        }


# ---------------------------------------------------------------------------
# Vulnerability scanner (Qualys / Tenable)
# ---------------------------------------------------------------------------

async def get_vulnerability_status(hostname: str) -> dict[str, Any]:
    """Query Qualys or Tenable for known vulnerabilities on a host.

    Environment:
        VULN_SCANNER_TYPE   -- "qualys" or "tenable" (default: tenable)
        QUALYS_BASE_URL, QUALYS_USER, QUALYS_PASSWORD
        TENABLE_BASE_URL, TENABLE_ACCESS_KEY, TENABLE_SECRET_KEY
    """
    scanner_type = os.environ.get("VULN_SCANNER_TYPE", "tenable").lower()

    if scanner_type == "qualys":
        return await _qualys_host_vulns(hostname)
    return await _tenable_host_vulns(hostname)


async def _tenable_host_vulns(hostname: str) -> dict[str, Any]:
    base_url = os.environ.get("TENABLE_BASE_URL", "https://cloud.tenable.com")
    access_key = os.environ.get("TENABLE_ACCESS_KEY", "")
    secret_key = os.environ.get("TENABLE_SECRET_KEY", "")

    if not access_key:
        return {"hostname": hostname, "found": False, "vulnerabilities": [], "error": "Tenable not configured"}

    @_RETRY
    async def _dispatch() -> dict[str, Any]:
        async with httpx.AsyncClient(
            base_url=base_url,
            headers={
                "X-ApiKeys": f"accessKey={access_key}; secretKey={secret_key}",
                "Accept": "application/json",
            },
            timeout=30,
        ) as c:
            # Find the asset
            assets_resp = await c.get(
                "/assets",
                params={"filter.0.filter": "host.hostname", "filter.0.quality": "eq", "filter.0.value": hostname},
            )
            assets_resp.raise_for_status()
            assets = assets_resp.json().get("assets", [])
            if not assets:
                return {"hostname": hostname, "found": False, "vulnerabilities": []}

            asset_id = assets[0].get("id")

            # Get vulnerabilities for the asset
            vulns_resp = await c.get(f"/workbenches/assets/{asset_id}/vulnerabilities")
            vulns_resp.raise_for_status()
            vulns = vulns_resp.json().get("vulnerabilities", [])

            return {
                "hostname": hostname,
                "found": True,
                "asset_id": asset_id,
                "vulnerability_count": len(vulns),
                "vulnerabilities": [
                    {
                        "plugin_id": v.get("plugin_id"),
                        "plugin_name": v.get("plugin_name"),
                        "severity": v.get("severity"),
                        "count": v.get("count"),
                    }
                    for v in vulns[:50]
                ],
            }

    try:
        return await _dispatch()
    except Exception as exc:
        logger.warning("tenable_vulns_failed", hostname=hostname, error=str(exc))
        return {"hostname": hostname, "found": False, "vulnerabilities": [], "error": str(exc)}


async def _qualys_host_vulns(hostname: str) -> dict[str, Any]:
    base_url = os.environ.get("QUALYS_BASE_URL", "https://qualysapi.qualys.com")
    user = os.environ.get("QUALYS_USER", "")
    password = os.environ.get("QUALYS_PASSWORD", "")

    if not user:
        return {"hostname": hostname, "found": False, "vulnerabilities": [], "error": "Qualys not configured"}

    @_RETRY
    async def _dispatch() -> dict[str, Any]:
        async with httpx.AsyncClient(
            base_url=base_url,
            auth=(user, password),
            headers={"X-Requested-With": "SOC-Analyst-Agent", "Accept": "application/json"},
            timeout=30,
        ) as c:
            resp = await c.post(
                "/api/2.0/fo/asset/host/vm/detection/",
                data={
                    "action": "list",
                    "host_dns": hostname,
                    "output_format": "JSON",
                },
            )
            resp.raise_for_status()
            data = resp.json()
            host_list = (
                data.get("HOST_LIST_VM_DETECTION_OUTPUT", {})
                .get("RESPONSE", {})
                .get("HOST_LIST", {})
                .get("HOST", [])
            )
            if not host_list:
                return {"hostname": hostname, "found": False, "vulnerabilities": []}

            host_entry = host_list[0] if isinstance(host_list, list) else host_list
            detections = host_entry.get("DETECTION_LIST", {}).get("DETECTION", [])
            if isinstance(detections, dict):
                detections = [detections]

            return {
                "hostname": hostname,
                "found": True,
                "vulnerability_count": len(detections),
                "vulnerabilities": [
                    {
                        "qid": d.get("QID"),
                        "severity": d.get("SEVERITY"),
                        "type": d.get("TYPE"),
                        "first_found": d.get("FIRST_FOUND_DATETIME"),
                        "last_found": d.get("LAST_FOUND_DATETIME"),
                        "status": d.get("STATUS"),
                    }
                    for d in detections[:50]
                ],
            }

    try:
        return await _dispatch()
    except Exception as exc:
        logger.warning("qualys_vulns_failed", hostname=hostname, error=str(exc))
        return {"hostname": hostname, "found": False, "vulnerabilities": [], "error": str(exc)}
