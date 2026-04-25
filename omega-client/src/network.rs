use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::process::Command;

use anyhow::Context;

use crate::config::{ClientConfig, DnsLeakGuardPolicy, KillSwitchPolicy, TunnelMode};

#[derive(Debug, Clone, PartialEq, Eq)]
struct RouteLookup {
    interface: String,
    gateway: Option<String>,
}

#[cfg(any(target_os = "windows", test))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct WindowsRoutePrintLookup {
    interface_addr: Ipv4Addr,
    gateway: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RouteFamily {
    Ipv4,
    Ipv6,
}

impl RouteFamily {
    fn address_family(self) -> &'static str {
        match self {
            Self::Ipv4 => "IPv4",
            Self::Ipv6 => "IPv6",
        }
    }

    fn default_next_hop(self) -> &'static str {
        match self {
            Self::Ipv4 => "0.0.0.0",
            Self::Ipv6 => "::",
        }
    }

    fn default_prefix_len(self) -> u8 {
        match self {
            Self::Ipv4 => 32,
            Self::Ipv6 => 128,
        }
    }
}

fn normalize_gateway(raw: &str) -> Option<String> {
    let value = raw.trim().trim_matches('"');
    if value.is_empty()
        || value.eq_ignore_ascii_case("on-link")
        || value == "0.0.0.0"
        || value == "::"
    {
        None
    } else {
        Some(value.to_string())
    }
}

#[cfg(any(target_os = "windows", test))]
fn parse_windows_route_lookup_csv(output: &str) -> Option<RouteLookup> {
    let mut lines = output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty());
    let _header = lines.next()?;
    let values = lines.next()?;
    let cols = values
        .trim_matches('"')
        .split("\",\"")
        .map(str::trim)
        .collect::<Vec<_>>();
    if cols.len() < 2 {
        return None;
    }
    Some(RouteLookup {
        interface: cols[0].to_string(),
        gateway: normalize_gateway(cols[1]),
    })
}

#[cfg(any(target_os = "windows", test))]
fn ipv4_mask_prefix_len(mask: Ipv4Addr) -> Option<u32> {
    let bits = u32::from(mask);
    let inverted = !bits;
    if inverted & inverted.wrapping_add(1) != 0 {
        return None;
    }
    Some(bits.count_ones())
}

#[cfg(any(target_os = "windows", test))]
fn parse_windows_route_print_ipv4(
    output: &str,
    target: Ipv4Addr,
) -> Option<WindowsRoutePrintLookup> {
    let target = u32::from(target);
    let mut in_active_routes = false;
    let mut best: Option<(u32, u32, WindowsRoutePrintLookup)> = None;

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.eq_ignore_ascii_case("Active Routes:") {
            in_active_routes = true;
            continue;
        }
        if !in_active_routes {
            continue;
        }
        if trimmed.starts_with("Persistent Routes:") || trimmed.starts_with("===") {
            break;
        }
        if trimmed.is_empty()
            || trimmed.starts_with("Network Destination")
            || trimmed.eq_ignore_ascii_case("None")
        {
            continue;
        }

        let cols = trimmed.split_whitespace().collect::<Vec<_>>();
        if cols.len() < 5 {
            continue;
        }

        let Ok(destination) = cols[0].parse::<Ipv4Addr>() else {
            continue;
        };
        let Ok(netmask) = cols[1].parse::<Ipv4Addr>() else {
            continue;
        };
        let Ok(interface_addr) = cols[3].parse::<Ipv4Addr>() else {
            continue;
        };
        let Some(prefix_len) = ipv4_mask_prefix_len(netmask) else {
            continue;
        };

        let mask = u32::from(netmask);
        if target & mask != u32::from(destination) & mask {
            continue;
        }

        let metric = cols[4].parse::<u32>().unwrap_or(u32::MAX);
        let lookup = WindowsRoutePrintLookup {
            interface_addr,
            gateway: normalize_gateway(cols[2]),
        };

        let should_replace = best
            .as_ref()
            .map(|(best_prefix_len, best_metric, _)| {
                prefix_len > *best_prefix_len
                    || (prefix_len == *best_prefix_len && metric < *best_metric)
            })
            .unwrap_or(true);
        if should_replace {
            best = Some((prefix_len, metric, lookup));
        }
    }

    best.map(|(_, _, lookup)| lookup)
}

#[cfg(any(target_os = "linux", test))]
fn parse_linux_route_lookup(output: &str) -> Option<RouteLookup> {
    let cols = output.split_whitespace().collect::<Vec<_>>();
    let interface = cols
        .windows(2)
        .find_map(|window| (window[0] == "dev").then(|| window[1].to_string()))?;
    let gateway = cols
        .windows(2)
        .find_map(|window| (window[0] == "via").then(|| window[1]))
        .and_then(normalize_gateway);

    Some(RouteLookup { interface, gateway })
}

#[cfg(any(target_os = "macos", test))]
fn parse_macos_route_get(output: &str) -> Option<RouteLookup> {
    let mut interface = None;
    let mut gateway = None;

    for line in output.lines() {
        let trimmed = line.trim();
        if let Some((key, value)) = trimmed.split_once(':') {
            match key.trim() {
                "interface" => interface = Some(value.trim().to_string()),
                "gateway" => gateway = normalize_gateway(value),
                _ => {}
            }
        }
    }

    Some(RouteLookup {
        interface: interface?,
        gateway,
    })
}

#[cfg(any(target_os = "macos", test))]
fn parse_macos_service_order(output: &str, interface: &str) -> Option<String> {
    let mut current_service = None;

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('(')
            && trimmed
                .chars()
                .nth(1)
                .map(|ch| ch.is_ascii_digit())
                .unwrap_or(false)
        {
            if let Some((_, service)) = trimmed.split_once(')') {
                current_service = Some(service.trim().trim_start_matches('*').trim().to_string());
            }
            continue;
        }

        if trimmed.contains("Device:") && trimmed.contains(interface) {
            return current_service.clone();
        }
    }

    None
}

#[cfg(any(target_os = "macos", test))]
fn parse_macos_dns_servers(output: &str) -> Option<Vec<String>> {
    let trimmed = output.trim();
    if trimmed.is_empty() {
        return Some(Vec::new());
    }
    if trimmed.starts_with("There aren't any DNS Servers set on ") {
        return Some(Vec::new());
    }

    let servers = trimmed
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    Some(servers)
}

#[cfg(target_os = "windows")]
#[derive(Clone)]
struct WindowsManagedRoute {
    family: RouteFamily,
    destination_prefix: String,
}

#[cfg(target_os = "windows")]
pub struct NetworkState {
    disabled_ipv6_adapters: Vec<String>,
    interface_alias: String,
    reset_dns: bool,
    firewall_rules_configured: bool,
    managed_routes: Vec<WindowsManagedRoute>,
    reset_ipv6_metric: bool,
}

#[cfg(target_os = "linux")]
pub struct NetworkState {
    interface_name: String,
    dns_configured: bool,
    managed_routes_v4: Vec<String>,
    managed_routes_v6: Vec<String>,
}

#[cfg(target_os = "macos")]
pub struct NetworkState {
    primary_service: Option<String>,
    previous_dns_servers: Option<Vec<String>>,
    dns_configured: bool,
    managed_routes_v4: Vec<String>,
    managed_routes_v6: Vec<String>,
}

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
pub struct NetworkState;

pub fn configure(
    server_addr: SocketAddr,
    tunnel_ip: Ipv4Addr,
    tunnel_ipv6: Option<Ipv6Addr>,
    interface_name: Option<&str>,
    interface_mtu: u16,
    config: &ClientConfig,
) -> anyhow::Result<Option<NetworkState>> {
    #[cfg(target_os = "windows")]
    let _ = interface_name;

    #[cfg(target_os = "windows")]
    {
        return configure_windows_routing(
            server_addr,
            tunnel_ip,
            tunnel_ipv6,
            interface_mtu,
            config,
        )
        .map(Some);
    }
    #[cfg(target_os = "linux")]
    {
        return configure_linux_network(
            server_addr,
            tunnel_ip,
            tunnel_ipv6,
            interface_name,
            interface_mtu,
            config,
        )
        .map(Some);
    }
    #[cfg(target_os = "macos")]
    {
        return configure_macos_network(
            server_addr,
            tunnel_ip,
            tunnel_ipv6,
            interface_name,
            interface_mtu,
            config,
        )
        .map(Some);
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        let _ = (
            server_addr,
            tunnel_ip,
            tunnel_ipv6,
            interface_name,
            interface_mtu,
            config,
        );
        Ok(None)
    }
}

pub fn cleanup(server_addr: SocketAddr, state: Option<&NetworkState>) {
    #[cfg(target_os = "windows")]
    {
        cleanup_windows_routing(server_addr, state);
    }
    #[cfg(target_os = "linux")]
    {
        cleanup_linux_network(server_addr, state);
    }
    #[cfg(target_os = "macos")]
    {
        cleanup_macos_network(server_addr, state);
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        let _ = (server_addr, state);
    }
}

pub fn cleanup_stale(server_addr: SocketAddr, config: &ClientConfig) {
    #[cfg(target_os = "windows")]
    {
        cleanup_stale_windows(server_addr, config);
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (server_addr, config);
    }
}

fn should_configure_tunnel_ipv6(config: &ClientConfig, tunnel_ipv6: Option<Ipv6Addr>) -> bool {
    config.should_tunnel_ipv6() && tunnel_ipv6.is_some()
}

fn warn_missing_tunnel_ipv6(config: &ClientConfig, tunnel_ipv6: Option<Ipv6Addr>) {
    if config.should_tunnel_ipv6() && tunnel_ipv6.is_none() {
        tracing::warn!(
            "OMEGA_IPV6_POLICY=tunnel was requested, but the server did not assign an IPv6 tunnel address; continuing with IPv4 tunnel routes"
        );
    }
}

fn normalize_dns_server(value: &str) -> String {
    value
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase()
}

fn dns_servers_cover_expected(actual: &[String], expected: &[String]) -> bool {
    let actual = actual
        .iter()
        .map(|value| normalize_dns_server(value))
        .collect::<std::collections::HashSet<_>>();

    expected
        .iter()
        .map(|value| normalize_dns_server(value))
        .all(|value| actual.contains(&value))
}

fn strict_kill_switch_supported(config: &ClientConfig) -> bool {
    if !matches!(config.kill_switch_policy, KillSwitchPolicy::Strict) {
        return true;
    }

    #[cfg(target_os = "windows")]
    {
        matches!(config.tunnel_mode, TunnelMode::Full)
    }
    #[cfg(not(target_os = "windows"))]
    {
        false
    }
}

#[cfg(target_os = "windows")]
fn configure_windows_routing(
    server_addr: SocketAddr,
    tunnel_ip: Ipv4Addr,
    tunnel_ipv6: Option<Ipv6Addr>,
    interface_mtu: u16,
    config: &ClientConfig,
) -> anyhow::Result<NetworkState> {
    use std::time::Duration;

    warn_missing_tunnel_ipv6(config, tunnel_ipv6);
    let configure_ipv6 = should_configure_tunnel_ipv6(config, tunnel_ipv6);

    tracing::info!(
        %server_addr,
        %tunnel_ip,
        tunnel_ipv6 = ?tunnel_ipv6,
        "configuring Windows routing tables"
    );

    let tunnel_ip_s = tunnel_ip.to_string();
    let mut if_index = String::new();
    let mut if_alias = String::new();

    for _ in 0..15 {
        let output_idx = Command::new("powershell")
            .args([
                "-Command",
                &format!(
                    "Get-NetIPAddress -IPAddress '{}' | Select-Object -ExpandProperty InterfaceIndex",
                    tunnel_ip_s
                ),
            ])
            .output();

        let output_alias = Command::new("powershell")
            .args([
                "-Command",
                &format!(
                    "Get-NetIPAddress -IPAddress '{}' | Select-Object -ExpandProperty InterfaceAlias",
                    tunnel_ip_s
                ),
            ])
            .output();

        if let (Ok(o_idx), Ok(o_alias)) = (output_idx, output_alias) {
            let idx_str = String::from_utf8_lossy(&o_idx.stdout).trim().to_string();
            let alias_str = String::from_utf8_lossy(&o_alias.stdout).trim().to_string();

            if !idx_str.is_empty() && !alias_str.is_empty() {
                if_index = idx_str;
                if_alias = alias_str;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(500));
    }

    if if_index.is_empty() || if_alias.is_empty() {
        anyhow::bail!("could not find Wintun interface");
    }

    let _ = Command::new("netsh")
        .args([
            "interface",
            "ipv4",
            "set",
            "subinterface",
            &if_alias,
            &format!("mtu={}", interface_mtu),
            "store=active",
        ])
        .status();

    run_powershell(&format!(
        "Set-NetIPInterface -InterfaceAlias '{}' -AddressFamily IPv4 -InterfaceMetric 1",
        powershell_quote(&if_alias)
    ))?;

    let reset_ipv6_metric = if configure_ipv6 {
        match run_powershell(&format!(
            "Set-NetIPInterface -InterfaceAlias '{}' -AddressFamily IPv6 -InterfaceMetric 1",
            powershell_quote(&if_alias)
        )) {
            Ok(()) => true,
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "failed to lower Wintun IPv6 metric; continuing with IPv4 tunnel routes"
                );
                false
            }
        }
    } else {
        false
    };

    let mut state = NetworkState {
        disabled_ipv6_adapters: if config.should_disable_ipv6() {
            configure_windows_ipv6_guard(&if_alias)
        } else {
            Vec::new()
        },
        interface_alias: if_alias.clone(),
        reset_dns: false,
        firewall_rules_configured: false,
        managed_routes: Vec::new(),
        reset_ipv6_metric,
    };

    let configure_result: anyhow::Result<()> = (|| {
        if !strict_kill_switch_supported(config) {
            anyhow::bail!(
                "OMEGA_KILL_SWITCH=strict is currently supported only for Windows full-tunnel mode"
            );
        }

        if matches!(config.kill_switch_policy, KillSwitchPolicy::Strict) {
            remove_windows_firewall_rules();
        }

        if config.should_set_tunnel_dns() && !config.dns_servers.is_empty() {
            let dns_ps = config
                .dns_servers
                .iter()
                .map(|value| format!("'{}'", value))
                .collect::<Vec<_>>()
                .join(",");
            let dns_result = run_powershell(&format!(
                "Set-DnsClientServerAddress -InterfaceAlias '{}' -ServerAddresses @({})",
                powershell_quote(&if_alias),
                dns_ps
            ));
            match dns_result {
                Ok(()) => {
                    state.reset_dns = true;
                    verify_windows_tunnel_dns(&if_alias, &config.dns_servers, config)?;
                }
                Err(err) if matches!(config.dns_leak_guard_policy, DnsLeakGuardPolicy::Strict) => {
                    return Err(err);
                }
                Err(err) => {
                    tracing::warn!(
                        error = %err,
                        "failed to set tunnel DNS; continuing because OMEGA_DNS_LEAK_GUARD is not strict"
                    );
                }
            }
        }

        if matches!(config.kill_switch_policy, KillSwitchPolicy::Strict)
            || matches!(config.dns_leak_guard_policy, DnsLeakGuardPolicy::Strict)
        {
            configure_windows_dns_firewall(&if_alias)?;
            state.firewall_rules_configured = true;
        }

        let server_lookup = find_windows_route(server_addr.ip()).with_context(|| {
            format!(
                "failed to resolve current Windows route to {}",
                server_addr.ip()
            )
        })?;
        let server_route = WindowsManagedRoute {
            family: socket_family(server_addr),
            destination_prefix: format!(
                "{}/{}",
                server_addr.ip(),
                socket_family(server_addr).default_prefix_len()
            ),
        };
        delete_windows_route(&server_route);
        add_windows_host_route(
            &server_route,
            &server_lookup.interface,
            server_lookup.gateway.as_deref(),
        )?;
        state.managed_routes.push(server_route);

        match config.tunnel_mode {
            TunnelMode::Full => {
                let full_v4 = [
                    WindowsManagedRoute {
                        family: RouteFamily::Ipv4,
                        destination_prefix: "0.0.0.0/1".to_string(),
                    },
                    WindowsManagedRoute {
                        family: RouteFamily::Ipv4,
                        destination_prefix: "128.0.0.0/1".to_string(),
                    },
                ];
                for route in full_v4 {
                    delete_windows_route(&route);
                    add_windows_host_route(&route, &if_index, None)?;
                    state.managed_routes.push(route);
                }

                if configure_ipv6 {
                    let full_v6 = [
                        WindowsManagedRoute {
                            family: RouteFamily::Ipv6,
                            destination_prefix: "::/1".to_string(),
                        },
                        WindowsManagedRoute {
                            family: RouteFamily::Ipv6,
                            destination_prefix: "8000::/1".to_string(),
                        },
                    ];
                    for route in full_v6 {
                        delete_windows_route(&route);
                        match add_windows_host_route(&route, &if_index, None) {
                            Ok(()) => state.managed_routes.push(route),
                            Err(err) => {
                                tracing::warn!(
                                    error = %err,
                                    destination = %route.destination_prefix,
                                    "failed to add Windows IPv6 tunnel route; IPv4 tunnel remains active"
                                );
                            }
                        }
                    }
                }
            }
            TunnelMode::Split => {
                for route in &config.split_routes {
                    let managed = WindowsManagedRoute {
                        family: RouteFamily::Ipv4,
                        destination_prefix: route.cidr.clone(),
                    };
                    delete_windows_route(&managed);
                    add_windows_host_route(&managed, &if_index, None)?;
                    state.managed_routes.push(managed);
                }
                if configure_ipv6 {
                    for route in &config.split_routes_v6 {
                        let managed = WindowsManagedRoute {
                            family: RouteFamily::Ipv6,
                            destination_prefix: route.cidr.clone(),
                        };
                        delete_windows_route(&managed);
                        match add_windows_host_route(&managed, &if_index, None) {
                            Ok(()) => state.managed_routes.push(managed),
                            Err(err) => {
                                tracing::warn!(
                                    error = %err,
                                    destination = %managed.destination_prefix,
                                    "failed to add Windows IPv6 split route; IPv4 tunnel remains active"
                                );
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    })();

    if let Err(err) = configure_result {
        tracing::warn!(error = %err, "Windows network configuration failed; rolling back partial changes");
        cleanup_windows_routing(server_addr, Some(&state));
        return Err(err);
    }

    Ok(state)
}

#[cfg(target_os = "windows")]
fn cleanup_windows_routing(server_addr: SocketAddr, state: Option<&NetworkState>) {
    if let Some(state) = state {
        if state.firewall_rules_configured {
            remove_windows_firewall_rules();
        }
        if state.reset_dns {
            let _ = run_powershell(&format!(
                "Set-DnsClientServerAddress -InterfaceAlias '{}' -ResetServerAddresses",
                powershell_quote(&state.interface_alias)
            ));
        }
        let _ = run_powershell(&format!(
            "Set-NetIPInterface -InterfaceAlias '{}' -AddressFamily IPv4 -AutomaticMetric Enabled",
            powershell_quote(&state.interface_alias)
        ));
        if state.reset_ipv6_metric {
            let _ = run_powershell(&format!(
                "Set-NetIPInterface -InterfaceAlias '{}' -AddressFamily IPv6 -AutomaticMetric Enabled",
                powershell_quote(&state.interface_alias)
            ));
        }
        restore_windows_ipv6_guard(&state.disabled_ipv6_adapters);
        for route in &state.managed_routes {
            delete_windows_route(route);
        }
    } else if matches!(server_addr, SocketAddr::V4(_) | SocketAddr::V6(_)) {
        let route = WindowsManagedRoute {
            family: socket_family(server_addr),
            destination_prefix: format!(
                "{}/{}",
                server_addr.ip(),
                socket_family(server_addr).default_prefix_len()
            ),
        };
        delete_windows_route(&route);
    }
}

#[cfg(target_os = "windows")]
fn cleanup_stale_windows(server_addr: SocketAddr, config: &ClientConfig) {
    remove_windows_firewall_rules();
    for route in stale_windows_routes(server_addr, config) {
        delete_windows_route(&route);
    }
}

#[cfg(any(target_os = "windows", test))]
fn stale_windows_routes(
    server_addr: SocketAddr,
    config: &ClientConfig,
) -> Vec<WindowsManagedRoute> {
    let mut routes = vec![WindowsManagedRoute {
        family: socket_family(server_addr),
        destination_prefix: format!(
            "{}/{}",
            server_addr.ip(),
            socket_family(server_addr).default_prefix_len()
        ),
    }];

    match config.tunnel_mode {
        TunnelMode::Full => {
            routes.push(WindowsManagedRoute {
                family: RouteFamily::Ipv4,
                destination_prefix: "0.0.0.0/1".to_string(),
            });
            routes.push(WindowsManagedRoute {
                family: RouteFamily::Ipv4,
                destination_prefix: "128.0.0.0/1".to_string(),
            });
            if config.should_tunnel_ipv6() {
                routes.push(WindowsManagedRoute {
                    family: RouteFamily::Ipv6,
                    destination_prefix: "::/1".to_string(),
                });
                routes.push(WindowsManagedRoute {
                    family: RouteFamily::Ipv6,
                    destination_prefix: "8000::/1".to_string(),
                });
            }
        }
        TunnelMode::Split => {
            routes.extend(config.split_routes.iter().map(|route| WindowsManagedRoute {
                family: RouteFamily::Ipv4,
                destination_prefix: route.cidr.clone(),
            }));
            routes.extend(
                config
                    .split_routes_v6
                    .iter()
                    .map(|route| WindowsManagedRoute {
                        family: RouteFamily::Ipv6,
                        destination_prefix: route.cidr.clone(),
                    }),
            );
        }
    }

    routes
}

#[cfg(target_os = "windows")]
fn find_windows_route(addr: IpAddr) -> anyhow::Result<RouteLookup> {
    match find_windows_route_via_find_net_route(addr) {
        Ok(lookup) => Ok(lookup),
        Err(primary_err) => match addr {
            IpAddr::V4(ipv4) => {
                tracing::warn!(
                    error = %primary_err,
                    %addr,
                    "Find-NetRoute did not return a usable server route; falling back to route print"
                );
                find_windows_route_via_route_print_ipv4(ipv4).with_context(|| {
                    format!(
                        "route print fallback also failed after Find-NetRoute failed: {primary_err}"
                    )
                })
            }
            IpAddr::V6(_) => Err(primary_err),
        },
    }
}

#[cfg(target_os = "windows")]
fn find_windows_route_via_find_net_route(addr: IpAddr) -> anyhow::Result<RouteLookup> {
    let stdout = run_powershell_output(&format!(
        "Find-NetRoute -RemoteIPAddress '{}' | Select-Object -First 1 InterfaceIndex,NextHop | ConvertTo-Csv -NoTypeInformation",
        addr
    ))
    .with_context(|| format!("failed to query Windows route to {addr}"))?;

    parse_windows_route_lookup_csv(&stdout)
        .ok_or_else(|| anyhow::anyhow!("could not parse Windows route lookup for {addr}"))
}

#[cfg(target_os = "windows")]
fn find_windows_route_via_route_print_ipv4(addr: Ipv4Addr) -> anyhow::Result<RouteLookup> {
    let output = Command::new("route")
        .args(["print", "-4"])
        .output()
        .context("failed to run route print -4")?;
    if !output.status.success() {
        anyhow::bail!(
            "route print -4 failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let printed = String::from_utf8_lossy(&output.stdout);
    let lookup = parse_windows_route_print_ipv4(&printed, addr)
        .ok_or_else(|| anyhow::anyhow!("could not parse Windows route print for {addr}"))?;
    let interface = find_windows_interface_index_for_ip(lookup.interface_addr)?;

    Ok(RouteLookup {
        interface,
        gateway: lookup.gateway,
    })
}

#[cfg(target_os = "windows")]
fn find_windows_interface_index_for_ip(addr: Ipv4Addr) -> anyhow::Result<String> {
    let stdout = run_powershell_output(&format!(
        "Get-NetIPAddress -IPAddress '{}' -AddressFamily IPv4 | Select-Object -First 1 -ExpandProperty InterfaceIndex",
        addr
    ))
    .with_context(|| format!("failed to resolve Windows interface index for {addr}"))?;

    stdout
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow::anyhow!("no Windows interface index found for {addr}"))
}

#[cfg(target_os = "windows")]
fn add_windows_host_route(
    route: &WindowsManagedRoute,
    interface_index: &str,
    next_hop: Option<&str>,
) -> anyhow::Result<()> {
    run_powershell(&format!(
        "New-NetRoute -AddressFamily {} -DestinationPrefix '{}' -InterfaceIndex {} -NextHop '{}' -RouteMetric 1 -PolicyStore ActiveStore | Out-Null",
        route.family.address_family(),
        route.destination_prefix,
        interface_index,
        next_hop.unwrap_or(route.family.default_next_hop())
    ))
}

#[cfg(target_os = "windows")]
fn delete_windows_route(route: &WindowsManagedRoute) {
    let _ = run_powershell(&format!(
        "Remove-NetRoute -AddressFamily {} -DestinationPrefix '{}' -Confirm:$false -ErrorAction SilentlyContinue | Out-Null",
        route.family.address_family(),
        route.destination_prefix
    ));
}

#[cfg(target_os = "windows")]
const OMEGA_FIREWALL_GROUP: &str = "Omega VPN";

#[cfg(target_os = "windows")]
fn remove_windows_firewall_rules() {
    let _ = run_powershell(&format!(
        "Remove-NetFirewallRule -DisplayGroup '{}' -ErrorAction SilentlyContinue | Out-Null",
        OMEGA_FIREWALL_GROUP
    ));
}

#[cfg(target_os = "windows")]
fn read_windows_dns_servers(interface_alias: &str) -> anyhow::Result<Vec<String>> {
    let output = run_powershell_output(&format!(
        "Get-DnsClientServerAddress -InterfaceAlias '{}' -ErrorAction Stop | ForEach-Object {{ $_.ServerAddresses }}",
        powershell_quote(interface_alias)
    ))?;

    Ok(output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect())
}

#[cfg(target_os = "windows")]
fn verify_windows_tunnel_dns(
    interface_alias: &str,
    expected: &[String],
    config: &ClientConfig,
) -> anyhow::Result<()> {
    let actual = read_windows_dns_servers(interface_alias)
        .with_context(|| format!("failed to read tunnel DNS servers from {interface_alias}"))?;

    if dns_servers_cover_expected(&actual, expected) {
        return Ok(());
    }

    let message = format!(
        "tunnel DNS readback mismatch on {interface_alias}: expected {:?}, actual {:?}",
        expected, actual
    );
    if matches!(config.dns_leak_guard_policy, DnsLeakGuardPolicy::Strict) {
        anyhow::bail!("OMEGA_DNS_LEAK_GUARD=strict: {message}");
    }

    tracing::warn!(%message, "tunnel DNS readback mismatch; continuing because DNS leak guard is not strict");
    Ok(())
}

#[cfg(target_os = "windows")]
fn windows_physical_adapter_aliases(wintun_alias: &str) -> Vec<String> {
    let list_cmd = format!(
        "Get-NetAdapter | Where-Object {{ $_.Status -eq 'Up' -and $_.HardwareInterface -eq $true -and $_.Name -ne '{}' -and $_.InterfaceDescription -notlike '*Wintun*' }} | Select-Object -ExpandProperty Name",
        powershell_quote(wintun_alias)
    );

    let Ok(output) = Command::new("powershell")
        .args(["-NoProfile", "-Command", &list_cmd])
        .output()
    else {
        return Vec::new();
    };

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

#[cfg(target_os = "windows")]
fn configure_windows_dns_firewall(wintun_alias: &str) -> anyhow::Result<()> {
    remove_windows_firewall_rules();

    for adapter in windows_physical_adapter_aliases(wintun_alias) {
        let adapter = powershell_quote(&adapter);
        for (proto, name) in [("UDP", "UDP"), ("TCP", "TCP")] {
            run_powershell(&format!(
                "New-NetFirewallRule -DisplayGroup '{}' -DisplayName 'Omega VPN DNS Leak Guard {} {}' -Direction Outbound -Action Block -Protocol {} -RemotePort 53 -InterfaceAlias '{}' -Profile Any | Out-Null",
                OMEGA_FIREWALL_GROUP,
                name,
                adapter,
                proto,
                adapter
            ))?;
        }
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn run_powershell(script: &str) -> anyhow::Result<()> {
    let status = Command::new("powershell")
        .args(["-Command", script])
        .status()
        .with_context(|| format!("failed to run PowerShell: {script}"))?;
    if status.success() {
        Ok(())
    } else {
        anyhow::bail!("PowerShell command failed: {script}");
    }
}

#[cfg(target_os = "windows")]
fn run_powershell_output(script: &str) -> anyhow::Result<String> {
    let output = Command::new("powershell")
        .args(["-NoProfile", "-Command", script])
        .output()
        .with_context(|| format!("failed to run PowerShell: {script}"))?;
    if !output.status.success() {
        anyhow::bail!(
            "PowerShell command failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(target_os = "windows")]
fn powershell_quote(value: &str) -> String {
    value.replace('\'', "''")
}

#[cfg(target_os = "windows")]
fn configure_windows_ipv6_guard(wintun_alias: &str) -> Vec<String> {
    let list_cmd = format!(
        "Get-NetAdapter | Where-Object {{ $_.Status -eq 'Up' -and $_.HardwareInterface -eq $true -and $_.Name -ne '{}' -and $_.InterfaceDescription -notlike '*Wintun*' }} | ForEach-Object {{ $binding = Get-NetAdapterBinding -Name $_.Name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue; if ($binding -and $binding.Enabled) {{ $_.Name }} }}",
        powershell_quote(wintun_alias)
    );

    let Ok(output) = Command::new("powershell")
        .args(["-Command", &list_cmd])
        .output()
    else {
        return Vec::new();
    };

    let adapters = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();

    for adapter in &adapters {
        let _ = run_powershell(&format!(
            "Disable-NetAdapterBinding -Name '{}' -ComponentID ms_tcpip6 -Confirm:$false | Out-Null",
            powershell_quote(adapter)
        ));
    }

    adapters
}

#[cfg(target_os = "windows")]
fn restore_windows_ipv6_guard(adapters: &[String]) {
    for adapter in adapters {
        let _ = run_powershell(&format!(
            "Enable-NetAdapterBinding -Name '{}' -ComponentID ms_tcpip6 -Confirm:$false | Out-Null",
            powershell_quote(adapter)
        ));
    }
}

#[cfg(target_os = "linux")]
fn configure_linux_network(
    server_addr: SocketAddr,
    _tunnel_ip: Ipv4Addr,
    tunnel_ipv6: Option<Ipv6Addr>,
    interface_name: Option<&str>,
    interface_mtu: u16,
    config: &ClientConfig,
) -> anyhow::Result<NetworkState> {
    warn_missing_tunnel_ipv6(config, tunnel_ipv6);
    if !strict_kill_switch_supported(config) {
        anyhow::bail!(
            "OMEGA_KILL_SWITCH=strict is currently implemented only on Windows full-tunnel mode"
        );
    }
    let configure_ipv6 = should_configure_tunnel_ipv6(config, tunnel_ipv6);

    let interface_name = interface_name.context("failed to determine tunnel interface name")?;
    run_status("ip", &["link", "set", "dev", interface_name, "up"])?;
    run_status(
        "ip",
        &[
            "link",
            "set",
            "dev",
            interface_name,
            "mtu",
            &interface_mtu.to_string(),
        ],
    )?;

    let mut state = NetworkState {
        interface_name: interface_name.to_string(),
        dns_configured: false,
        managed_routes_v4: Vec::new(),
        managed_routes_v6: Vec::new(),
    };

    let server_lookup = find_linux_route(server_addr.ip())
        .with_context(|| format!("failed to resolve Linux route to {}", server_addr.ip()))?;
    let server_prefix = format!(
        "{}/{}",
        server_addr.ip(),
        socket_family(server_addr).default_prefix_len()
    );
    add_linux_route(
        &server_prefix,
        socket_family(server_addr),
        interface_name,
        server_lookup.gateway.as_deref(),
    )?;
    track_route(&mut state, socket_family(server_addr), server_prefix);

    match config.tunnel_mode {
        TunnelMode::Full => {
            for prefix in ["0.0.0.0/1", "128.0.0.0/1"] {
                add_linux_route(prefix, RouteFamily::Ipv4, interface_name, None)?;
                track_route(&mut state, RouteFamily::Ipv4, prefix.to_string());
            }
            if configure_ipv6 {
                for prefix in ["::/1", "8000::/1"] {
                    match add_linux_route(prefix, RouteFamily::Ipv6, interface_name, None) {
                        Ok(()) => track_route(&mut state, RouteFamily::Ipv6, prefix.to_string()),
                        Err(err) => tracing::warn!(
                            error = %err,
                            prefix,
                            "failed to add Linux IPv6 tunnel route; IPv4 tunnel remains active"
                        ),
                    }
                }
            }
        }
        TunnelMode::Split => {
            for route in &config.split_routes {
                add_linux_route(&route.cidr, RouteFamily::Ipv4, interface_name, None)?;
                track_route(&mut state, RouteFamily::Ipv4, route.cidr.clone());
            }
            if configure_ipv6 {
                for route in &config.split_routes_v6 {
                    match add_linux_route(&route.cidr, RouteFamily::Ipv6, interface_name, None) {
                        Ok(()) => track_route(&mut state, RouteFamily::Ipv6, route.cidr.clone()),
                        Err(err) => tracing::warn!(
                            error = %err,
                            prefix = %route.cidr,
                            "failed to add Linux IPv6 split route; IPv4 tunnel remains active"
                        ),
                    }
                }
            }
        }
    }

    if config.should_set_tunnel_dns() && !config.dns_servers.is_empty() {
        configure_linux_dns(interface_name, &config.dns_servers)?;
        verify_linux_tunnel_dns(interface_name, &config.dns_servers, config)?;
        state.dns_configured = true;
    }

    Ok(state)
}

#[cfg(target_os = "linux")]
fn cleanup_linux_network(server_addr: SocketAddr, state: Option<&NetworkState>) {
    if let Some(state) = state {
        for prefix in &state.managed_routes_v4 {
            let _ = Command::new("ip").args(["route", "del", prefix]).status();
        }
        for prefix in &state.managed_routes_v6 {
            let _ = Command::new("ip")
                .args(["-6", "route", "del", prefix])
                .status();
        }
        if state.dns_configured {
            let _ = revert_linux_dns(&state.interface_name);
        }
    } else {
        let prefix = format!(
            "{}/{}",
            server_addr.ip(),
            socket_family(server_addr).default_prefix_len()
        );
        match socket_family(server_addr) {
            RouteFamily::Ipv4 => {
                let _ = Command::new("ip").args(["route", "del", &prefix]).status();
            }
            RouteFamily::Ipv6 => {
                let _ = Command::new("ip")
                    .args(["-6", "route", "del", &prefix])
                    .status();
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn find_linux_route(addr: IpAddr) -> anyhow::Result<RouteLookup> {
    let output = match addr {
        IpAddr::V4(ip) => Command::new("ip")
            .args(["route", "get", &ip.to_string()])
            .output(),
        IpAddr::V6(ip) => Command::new("ip")
            .args(["-6", "route", "get", &ip.to_string()])
            .output(),
    }
    .with_context(|| format!("failed to query Linux route to {addr}"))?;

    parse_linux_route_lookup(&String::from_utf8_lossy(&output.stdout))
        .ok_or_else(|| anyhow::anyhow!("could not parse Linux route lookup for {addr}"))
}

#[cfg(target_os = "linux")]
fn add_linux_route(
    prefix: &str,
    family: RouteFamily,
    interface_name: &str,
    gateway: Option<&str>,
) -> anyhow::Result<()> {
    let mut args = match family {
        RouteFamily::Ipv4 => vec!["route", "replace", prefix],
        RouteFamily::Ipv6 => vec!["-6", "route", "replace", prefix],
    };
    if let Some(gateway) = gateway {
        args.extend(["via", gateway]);
    }
    args.extend(["dev", interface_name, "metric", "1"]);
    run_status("ip", &args)
}

#[cfg(target_os = "linux")]
fn configure_linux_dns(interface_name: &str, dns_servers: &[String]) -> anyhow::Result<()> {
    if let Some(tool) = linux_dns_tool() {
        match tool {
            LinuxDnsTool::ResolveCtl => {
                let mut dns_args = vec!["dns", interface_name];
                dns_args.extend(dns_servers.iter().map(String::as_str));
                run_status("resolvectl", &dns_args)?;
                run_status("resolvectl", &["domain", interface_name, "~."])?;
                run_status("resolvectl", &["default-route", interface_name, "yes"])?;
                Ok(())
            }
            LinuxDnsTool::SystemdResolve => {
                let mut args = vec![
                    format!("--interface={interface_name}"),
                    "--set-domain=~.".to_string(),
                ];
                for server in dns_servers {
                    args.push(format!("--set-dns={server}"));
                }
                let arg_refs = args.iter().map(String::as_str).collect::<Vec<_>>();
                run_status("systemd-resolve", &arg_refs)
            }
        }
    } else {
        anyhow::bail!(
            "tunnel DNS requested but neither resolvectl nor systemd-resolve is available"
        );
    }
}

#[cfg(target_os = "linux")]
fn revert_linux_dns(interface_name: &str) -> anyhow::Result<()> {
    if let Some(tool) = linux_dns_tool() {
        match tool {
            LinuxDnsTool::ResolveCtl => run_status("resolvectl", &["revert", interface_name]),
            LinuxDnsTool::SystemdResolve => run_status(
                "systemd-resolve",
                &[&format!("--interface={interface_name}"), "--revert"],
            ),
        }
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn verify_linux_tunnel_dns(
    interface_name: &str,
    expected: &[String],
    config: &ClientConfig,
) -> anyhow::Result<()> {
    if !matches!(config.dns_leak_guard_policy, DnsLeakGuardPolicy::Strict) {
        return Ok(());
    }

    let Some(LinuxDnsTool::ResolveCtl) = linux_dns_tool() else {
        return Ok(());
    };

    let output = Command::new("resolvectl")
        .args(["dns", interface_name])
        .output()
        .with_context(|| format!("failed to read Linux DNS servers for {interface_name}"))?;
    let raw = String::from_utf8_lossy(&output.stdout);
    let actual = raw
        .split_whitespace()
        .filter(|value| value.parse::<IpAddr>().is_ok())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    if dns_servers_cover_expected(&actual, expected) {
        Ok(())
    } else {
        anyhow::bail!(
            "OMEGA_DNS_LEAK_GUARD=strict: tunnel DNS readback mismatch on {interface_name}: expected {:?}, actual {:?}",
            expected,
            actual
        );
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
enum LinuxDnsTool {
    ResolveCtl,
    SystemdResolve,
}

#[cfg(target_os = "linux")]
fn linux_dns_tool() -> Option<LinuxDnsTool> {
    if Command::new("resolvectl").arg("--version").output().is_ok() {
        Some(LinuxDnsTool::ResolveCtl)
    } else if Command::new("systemd-resolve")
        .arg("--version")
        .output()
        .is_ok()
    {
        Some(LinuxDnsTool::SystemdResolve)
    } else {
        None
    }
}

#[cfg(target_os = "macos")]
fn configure_macos_network(
    server_addr: SocketAddr,
    _tunnel_ip: Ipv4Addr,
    tunnel_ipv6: Option<Ipv6Addr>,
    interface_name: Option<&str>,
    interface_mtu: u16,
    config: &ClientConfig,
) -> anyhow::Result<NetworkState> {
    warn_missing_tunnel_ipv6(config, tunnel_ipv6);
    if !strict_kill_switch_supported(config) {
        anyhow::bail!(
            "OMEGA_KILL_SWITCH=strict is currently implemented only on Windows full-tunnel mode"
        );
    }
    let configure_ipv6 = should_configure_tunnel_ipv6(config, tunnel_ipv6);

    let interface_name = interface_name.context("failed to determine tunnel interface name")?;
    run_status(
        "ifconfig",
        &[interface_name, "mtu", &interface_mtu.to_string(), "up"],
    )?;

    let mut state = NetworkState {
        primary_service: None,
        previous_dns_servers: None,
        dns_configured: false,
        managed_routes_v4: Vec::new(),
        managed_routes_v6: Vec::new(),
    };

    let server_lookup = find_macos_route(server_addr.ip())
        .with_context(|| format!("failed to resolve macOS route to {}", server_addr.ip()))?;
    let server_prefix = format!(
        "{}/{}",
        server_addr.ip(),
        socket_family(server_addr).default_prefix_len()
    );
    add_macos_host_route(&server_prefix, socket_family(server_addr), &server_lookup)?;
    track_route(&mut state, socket_family(server_addr), server_prefix);

    match config.tunnel_mode {
        TunnelMode::Full => {
            for prefix in ["0.0.0.0/1", "128.0.0.0/1"] {
                add_macos_interface_route(prefix, RouteFamily::Ipv4, interface_name)?;
                track_route(&mut state, RouteFamily::Ipv4, prefix.to_string());
            }
            if configure_ipv6 {
                for prefix in ["::/1", "8000::/1"] {
                    match add_macos_interface_route(prefix, RouteFamily::Ipv6, interface_name) {
                        Ok(()) => track_route(&mut state, RouteFamily::Ipv6, prefix.to_string()),
                        Err(err) => tracing::warn!(
                            error = %err,
                            prefix,
                            "failed to add macOS IPv6 tunnel route; IPv4 tunnel remains active"
                        ),
                    }
                }
            }
        }
        TunnelMode::Split => {
            for route in &config.split_routes {
                add_macos_interface_route(&route.cidr, RouteFamily::Ipv4, interface_name)?;
                track_route(&mut state, RouteFamily::Ipv4, route.cidr.clone());
            }
            if configure_ipv6 {
                for route in &config.split_routes_v6 {
                    match add_macos_interface_route(&route.cidr, RouteFamily::Ipv6, interface_name)
                    {
                        Ok(()) => track_route(&mut state, RouteFamily::Ipv6, route.cidr.clone()),
                        Err(err) => tracing::warn!(
                            error = %err,
                            prefix = %route.cidr,
                            "failed to add macOS IPv6 split route; IPv4 tunnel remains active"
                        ),
                    }
                }
            }
        }
    }

    if config.should_set_tunnel_dns() && !config.dns_servers.is_empty() {
        let primary_service = find_macos_primary_service(&server_lookup.interface)
            .context("failed to resolve primary macOS network service for DNS")?;
        let previous_dns_servers = read_macos_dns_servers(&primary_service)?;
        configure_macos_dns(&primary_service, &config.dns_servers)?;
        verify_macos_tunnel_dns(&primary_service, &config.dns_servers, config)?;
        state.primary_service = Some(primary_service);
        state.previous_dns_servers = Some(previous_dns_servers);
        state.dns_configured = true;
    }

    Ok(state)
}

#[cfg(target_os = "macos")]
fn cleanup_macos_network(server_addr: SocketAddr, state: Option<&NetworkState>) {
    if let Some(state) = state {
        for prefix in &state.managed_routes_v4 {
            let _ = Command::new("route")
                .args(["-n", "delete", "-net", prefix])
                .status();
        }
        for prefix in &state.managed_routes_v6 {
            let _ = Command::new("route")
                .args(["-n", "delete", "-inet6", "-net", prefix])
                .status();
        }
        if state.dns_configured {
            if let (Some(service), Some(previous)) = (
                state.primary_service.as_ref(),
                state.previous_dns_servers.as_ref(),
            ) {
                if previous.is_empty() {
                    let _ = Command::new("networksetup")
                        .args(["-setdnsservers", service, "empty"])
                        .status();
                } else {
                    let mut args = vec!["-setdnsservers", service.as_str()];
                    args.extend(previous.iter().map(String::as_str));
                    let _ = Command::new("networksetup").args(&args).status();
                }
            }
        }
    } else {
        match socket_family(server_addr) {
            RouteFamily::Ipv4 => {
                let _ = Command::new("route")
                    .args(["-n", "delete", "-host", &server_addr.ip().to_string()])
                    .status();
            }
            RouteFamily::Ipv6 => {
                let _ = Command::new("route")
                    .args([
                        "-n",
                        "delete",
                        "-inet6",
                        "-host",
                        &server_addr.ip().to_string(),
                    ])
                    .status();
            }
        }
    }
}

#[cfg(target_os = "macos")]
fn find_macos_route(addr: IpAddr) -> anyhow::Result<RouteLookup> {
    let output = match addr {
        IpAddr::V4(ip) => Command::new("route")
            .args(["-n", "get", "-inet", &ip.to_string()])
            .output(),
        IpAddr::V6(ip) => Command::new("route")
            .args(["-n", "get", "-inet6", &ip.to_string()])
            .output(),
    }
    .with_context(|| format!("failed to query macOS route to {addr}"))?;

    parse_macos_route_get(&String::from_utf8_lossy(&output.stdout))
        .ok_or_else(|| anyhow::anyhow!("could not parse macOS route lookup for {addr}"))
}

#[cfg(target_os = "macos")]
fn add_macos_host_route(
    prefix: &str,
    family: RouteFamily,
    lookup: &RouteLookup,
) -> anyhow::Result<()> {
    let host = prefix.split('/').next().unwrap_or(prefix);
    let mut args = vec!["-n", "add"];
    if matches!(family, RouteFamily::Ipv6) {
        args.push("-inet6");
    }
    args.push("-host");
    args.push(host);
    if let Some(gateway) = lookup.gateway.as_deref() {
        args.push(gateway);
    } else {
        args.push("-interface");
        args.push(&lookup.interface);
    }
    run_status("route", &args)
}

#[cfg(target_os = "macos")]
fn add_macos_interface_route(
    prefix: &str,
    family: RouteFamily,
    interface_name: &str,
) -> anyhow::Result<()> {
    let mut args = vec!["-n", "add"];
    if matches!(family, RouteFamily::Ipv6) {
        args.push("-inet6");
    }
    args.extend(["-net", prefix, "-interface", interface_name]);
    run_status("route", &args)
}

#[cfg(target_os = "macos")]
fn find_macos_primary_service(interface: &str) -> anyhow::Result<String> {
    let output = Command::new("networksetup")
        .arg("-listnetworkserviceorder")
        .output()
        .context("failed to inspect macOS network service order")?;
    parse_macos_service_order(&String::from_utf8_lossy(&output.stdout), interface).ok_or_else(
        || anyhow::anyhow!("could not map macOS interface {interface} to a network service"),
    )
}

#[cfg(target_os = "macos")]
fn read_macos_dns_servers(service: &str) -> anyhow::Result<Vec<String>> {
    let output = Command::new("networksetup")
        .args(["-getdnsservers", service])
        .output()
        .with_context(|| format!("failed to read DNS servers for macOS service {service}"))?;
    parse_macos_dns_servers(&String::from_utf8_lossy(&output.stdout))
        .ok_or_else(|| anyhow::anyhow!("failed to parse DNS servers for macOS service {service}"))
}

#[cfg(target_os = "macos")]
fn configure_macos_dns(service: &str, dns_servers: &[String]) -> anyhow::Result<()> {
    let mut args = vec!["-setdnsservers", service];
    args.extend(dns_servers.iter().map(String::as_str));
    run_status("networksetup", &args)
}

#[cfg(target_os = "macos")]
fn verify_macos_tunnel_dns(
    service: &str,
    expected: &[String],
    config: &ClientConfig,
) -> anyhow::Result<()> {
    let actual = read_macos_dns_servers(service)?;
    if dns_servers_cover_expected(&actual, expected) {
        return Ok(());
    }

    if matches!(config.dns_leak_guard_policy, DnsLeakGuardPolicy::Strict) {
        anyhow::bail!(
            "OMEGA_DNS_LEAK_GUARD=strict: tunnel DNS readback mismatch on {service}: expected {:?}, actual {:?}",
            expected,
            actual
        );
    }

    tracing::warn!(
        service,
        expected = ?expected,
        actual = ?actual,
        "tunnel DNS readback mismatch; continuing because DNS leak guard is not strict"
    );
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn run_status(program: &str, args: &[&str]) -> anyhow::Result<()> {
    let status = Command::new(program)
        .args(args)
        .status()
        .with_context(|| format!("failed to execute {} {:?}", program, args))?;
    if status.success() {
        Ok(())
    } else {
        anyhow::bail!("command failed: {} {:?}", program, args);
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn track_route(state: &mut NetworkState, family: RouteFamily, prefix: String) {
    match family {
        RouteFamily::Ipv4 => state.managed_routes_v4.push(prefix),
        RouteFamily::Ipv6 => state.managed_routes_v6.push(prefix),
    }
}

fn socket_family(addr: SocketAddr) -> RouteFamily {
    if addr.is_ipv4() {
        RouteFamily::Ipv4
    } else {
        RouteFamily::Ipv6
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        ConnectionProfile, DnsLeakGuardPolicy, DnsPolicy, Ipv4Route, Ipv6Policy, Ipv6Route,
        KillSwitchPolicy, MorphingPolicy, MtuPolicy, TransportPolicy, TunnelMode,
    };
    use std::path::PathBuf;

    fn test_config(ipv6_policy: Ipv6Policy) -> ClientConfig {
        ClientConfig {
            profile: ConnectionProfile::Gaming,
            morphing_policy: MorphingPolicy::Off,
            tunnel_mode: TunnelMode::Full,
            dns_policy: DnsPolicy::Tunnel,
            ipv6_policy,
            mtu_policy: MtuPolicy::Auto,
            transport_policy: TransportPolicy::Udp,
            kill_switch_policy: KillSwitchPolicy::Soft,
            dns_leak_guard_policy: DnsLeakGuardPolicy::Warn,
            requested_mtu: 1380,
            mtu_probe_timeout_ms: 450,
            keepalive_secs: 25,
            udp_rcvbuf: 8 * 1024 * 1024,
            udp_sndbuf: 8 * 1024 * 1024,
            dns_servers: vec!["1.1.1.1".to_string()],
            split_routes: Vec::<Ipv4Route>::new(),
            split_routes_v6: Vec::<Ipv6Route>::new(),
            network_diag: true,
            diagnostics_path: PathBuf::from("diagnostics.json"),
            handshake_attempts: 5,
            handshake_timeout_ms: 1500,
            handshake_backoff_ms: 500,
        }
    }

    #[test]
    fn parses_windows_route_lookup_csv() {
        let lookup = parse_windows_route_lookup_csv(
            "\"InterfaceIndex\",\"NextHop\"\r\n\"7\",\"fe80::1\"\r\n",
        )
        .unwrap();

        assert_eq!(lookup.interface, "7");
        assert_eq!(lookup.gateway.as_deref(), Some("fe80::1"));
    }

    #[test]
    fn parses_windows_route_print_ipv4_best_match() {
        let lookup = parse_windows_route_print_ipv4(
            "\
===========================================================================
Interface List
 16...04 92 26 15 4e 53 ......Realtek PCIe GbE Family Controller #2
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1      192.168.1.4     55
     72.56.80.236  255.255.255.255      192.168.1.1      192.168.1.4     56
      192.168.1.0    255.255.255.0         On-link       192.168.1.4    311
===========================================================================
Persistent Routes:
  None
",
            "72.56.88.224".parse().unwrap(),
        )
        .unwrap();

        assert_eq!(lookup.interface_addr, Ipv4Addr::new(192, 168, 1, 4));
        assert_eq!(lookup.gateway.as_deref(), Some("192.168.1.1"));
    }

    #[test]
    fn parses_linux_route_lookup_output() {
        let lookup = parse_linux_route_lookup(
            "2001:db8::10 via fe80::1 dev wlan0 proto ra src 2001:db8::20 metric 600 pref medium",
        )
        .unwrap();

        assert_eq!(lookup.interface, "wlan0");
        assert_eq!(lookup.gateway.as_deref(), Some("fe80::1"));
    }

    #[test]
    fn parses_macos_route_get_output() {
        let lookup = parse_macos_route_get(
            "\
   route to: 2001:4860:4860::8888\n\
destination: default\n\
       mask: default\n\
    gateway: fe80::1%en0\n\
  interface: en0\n",
        )
        .unwrap();

        assert_eq!(lookup.interface, "en0");
        assert_eq!(lookup.gateway.as_deref(), Some("fe80::1%en0"));
    }

    #[test]
    fn parses_primary_service_from_networksetup_output() {
        let service = parse_macos_service_order(
            "\
An asterisk (*) denotes that a network service is disabled.\n\
(1) Wi-Fi\n\
(Hardware Port: Wi-Fi, Device: en0)\n\
(2) Thunderbolt Bridge\n\
(Hardware Port: Thunderbolt Bridge, Device: bridge0)\n",
            "en0",
        );

        assert_eq!(service.as_deref(), Some("Wi-Fi"));
    }

    #[test]
    fn parses_macos_dns_servers() {
        assert_eq!(
            parse_macos_dns_servers("8.8.8.8\n2606:4700:4700::1111\n"),
            Some(vec![
                "8.8.8.8".to_string(),
                "2606:4700:4700::1111".to_string()
            ])
        );
        assert_eq!(
            parse_macos_dns_servers("There aren't any DNS Servers set on Wi-Fi.\n"),
            Some(Vec::new())
        );
    }

    #[test]
    fn dns_server_readback_matches_expected_subset() {
        let actual = vec![
            "1.1.1.1".to_string(),
            "[2606:4700:4700::1111]".to_string(),
            "8.8.8.8".to_string(),
        ];
        let expected = vec!["2606:4700:4700::1111".to_string(), "1.1.1.1".to_string()];

        assert!(dns_servers_cover_expected(&actual, &expected));
        assert!(!dns_servers_cover_expected(
            &actual,
            &["9.9.9.9".to_string()]
        ));
    }

    #[test]
    fn strict_kill_switch_support_is_platform_and_mode_scoped() {
        let mut config = test_config(Ipv6Policy::Tunnel);
        config.kill_switch_policy = KillSwitchPolicy::Strict;
        config.tunnel_mode = TunnelMode::Full;

        #[cfg(target_os = "windows")]
        assert!(strict_kill_switch_supported(&config));
        #[cfg(not(target_os = "windows"))]
        assert!(!strict_kill_switch_supported(&config));

        config.tunnel_mode = TunnelMode::Split;
        assert!(!strict_kill_switch_supported(&config));
    }

    #[test]
    fn tunnel_ipv6_routing_requires_policy_and_assigned_address() {
        let assigned = Some("fd70:7::2".parse().unwrap());

        assert!(should_configure_tunnel_ipv6(
            &test_config(Ipv6Policy::Tunnel),
            assigned
        ));
        assert!(!should_configure_tunnel_ipv6(
            &test_config(Ipv6Policy::Tunnel),
            None
        ));
        assert!(!should_configure_tunnel_ipv6(
            &test_config(Ipv6Policy::Disabled),
            assigned
        ));
    }

    #[test]
    fn stale_windows_routes_include_server_and_full_tunnel_prefixes() {
        let routes = stale_windows_routes(
            "72.56.88.224:443".parse().unwrap(),
            &test_config(Ipv6Policy::Tunnel),
        );
        let prefixes = routes
            .iter()
            .map(|route| route.destination_prefix.as_str())
            .collect::<Vec<_>>();

        assert!(prefixes.contains(&"72.56.88.224/32"));
        assert!(prefixes.contains(&"0.0.0.0/1"));
        assert!(prefixes.contains(&"128.0.0.0/1"));
        assert!(prefixes.contains(&"::/1"));
        assert!(prefixes.contains(&"8000::/1"));
    }
}
