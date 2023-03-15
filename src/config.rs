use std::str::FromStr;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};

/// Configuration file template
pub const CLIENT_CONFIG_TEMPLATE: &str = r#"## Configuration for rqst VPN client

[[path-groups]]
name = "localnet"
ipnets = ["192.168.1.0/24", "192.168.179.0/24", "2001:db8::/32"]

[[path-groups]]
name = "localnet-not-metered"
ipnets = ["192.168.1.0/24", "192.168.179.0/24", "2001:db8::/32"]
iftypes = ["not-metered"]

[[path-groups]]
name = "any-metered"
iftypes = ["metered"]

[[tunnels]]
dscp = [0, 40]
path-group = "localnet-not-metered"

[exclude-ipv4net]
exclude-ipnets = ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
include-ipnets = ["192.168.1.0/24"]

[exclude-ipv6net]
exclude-ipnets = ["::1/128", "fe80::/64"]
[exclude-iftype]
iftypes = ["metered"]
"#;

fn default_ipnets() -> Vec<IpNet> {
    vec![
        "0.0.0.0/0".parse::<IpNet>().unwrap(),
        "::/0".parse::<IpNet>().unwrap(),
    ]
}

fn default_iftypes() -> Vec<IfType> {
    vec![
        IfType::Metered,
        IfType::NotMetered,
    ]
}

fn default_exclude_ipv4net() -> ExcludeIpv4Net {
    ExcludeIpv4Net {
        exclude_ipnets: Vec::new(),
        include_ipnets: Vec::new(),   
    }
}

fn default_exclude_ipv6net() -> ExcludeIpv6Net {
    ExcludeIpv6Net {
        exclude_ipnets: Vec::new(),
        include_ipnets: Vec::new(),   
    }
}

fn default_exclude_iftype() -> ExcludeIfType {
    ExcludeIfType {
        iftypes: Vec::new()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientConfig {
    #[serde(rename = "path-groups" ,default)]
    pub path_groups: Vec<PathGroup>,

    #[serde(default)]
    pub tunnels: Vec<Tunnel>,

    #[serde(rename = "exclude-ipv4net", default = "default_exclude_ipv4net")]
    pub exclude_ipv4net: ExcludeIpv4Net,

    #[serde(rename = "exclude-ipv6net", default = "default_exclude_ipv6net")]
    pub exclude_ipv6net: ExcludeIpv6Net,

    #[serde(rename = "exclude-iftype", default = "default_exclude_iftype")]
    pub exclude_iftype: ExcludeIfType,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathGroup {
    pub name: String,
    #[serde(default = "default_ipnets")]
    pub ipnets: Vec<IpNet>,
    
    #[serde(default = "default_iftypes")]
    pub iftypes: Vec<IfType>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum IfType {
    #[serde(rename = "metered")]
    Metered,

    #[serde(rename = "not-metered")]
    NotMetered,
}

impl IfType {
    pub fn is_metered(&self) -> bool {
        match self {
            IfType::Metered => true,
            IfType::NotMetered => false
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tunnel {
    #[serde(default)]
    pub dscp: Vec<u8>,
    #[serde(rename = "path-group")]
    pub path_group: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExcludeIpv4Net {
    #[serde(rename = "exclude-ipnets", default)]
    pub exclude_ipnets: Vec<Ipv4Net>,
    #[serde(rename = "include-ipnets", default)]
    pub include_ipnets: Vec<Ipv4Net>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExcludeIpv6Net {
    #[serde(rename = "exclude-ipnets", default)]
    pub exclude_ipnets: Vec<Ipv6Net>,
    #[serde(rename = "include-ipnets", default)]
    pub include_ipnets: Vec<Ipv6Net>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExcludeIfType {
    #[serde(default)]
    pub iftypes: Vec<IfType>,

}
mod test {
    use super::*;

    const CLIENT_CONFIG: &str = r#"
        [[path-groups]]
        name = "localnet"
        ipnets = ["192.168.1.0/24", "192.168.179.0/24", "2001:db8::/32"]
        [[path-groups]]
        name = "localnet-not-metered"
        ipnets = ["192.168.1.0/24", "192.168.179.0/24", "2001:db8::/32"]
        iftypes = ["not-metered"]
        [[path-groups]]
        name = "any-metered"
        iftypes = ["metered"]
        [[tunnels]]
        dscp = [0, 40]
        path-group = "localnet-not-metered"
        [exclude-ipv4net]
        exclude-ipnets = ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
        include-ipnets = ["192.168.1.0/24"]
        [exclude-ipv6net]
        exclude-ipnets = ["::1/128", "fe80::/64"]
        [exclude-iftype]
        iftypes = ["metered"]
    "#;

    #[test]
    fn client_config() {
        let cfg: ClientConfig = toml::from_str(CLIENT_CONFIG).unwrap();

        assert_eq!(
            cfg.path_groups,
            vec![
                PathGroup {
                    name: "localnet".to_string(),
                    ipnets: vec![
                        "192.168.1.0/24".parse::<IpNet>().unwrap(),
                        "192.168.179.0/24".parse::<IpNet>().unwrap(),
                        "2001:db8::/32".parse::<IpNet>().unwrap(),
                    ],
                    iftypes: vec![
                        IfType::Metered,
                        IfType::NotMetered,
                    ],
                },
                PathGroup {
                    name: "localnet-not-metered".to_string(),
                    ipnets: vec![
                        "192.168.1.0/24".parse::<IpNet>().unwrap(),
                        "192.168.179.0/24".parse::<IpNet>().unwrap(),
                        "2001:db8::/32".parse::<IpNet>().unwrap(),
                    ],
                    iftypes: vec![
                        IfType::NotMetered,
                    ],
                },
                PathGroup {
                    name: "any-metered".to_string(),
                    ipnets: vec![
                        "0.0.0.0/0".parse::<IpNet>().unwrap(),
                        "::/0".parse::<IpNet>().unwrap(),
                    ],
                    iftypes: vec![
                        IfType::Metered,
                    ],
                },
            ]
        );

        assert_eq!(
            cfg.tunnels,
            vec![
                Tunnel {
                    dscp: vec![0, 40],
                    path_group: "localnet-not-metered".to_string(),
                },
            ]
        );

        assert_eq!(
            cfg.exclude_ipv4net,
            ExcludeIpv4Net {
                exclude_ipnets: vec![
                    Ipv4Net::from_str("127.0.0.0/8").unwrap(),
                    Ipv4Net::from_str("10.0.0.0/8").unwrap(),
                    Ipv4Net::from_str("172.16.0.0/12").unwrap(),
                    Ipv4Net::from_str("192.168.0.0/16").unwrap(),
                ],
                include_ipnets: vec![
                    Ipv4Net::from_str("192.168.1.0/24").unwrap(),
                ]
            }
        );

        assert_eq!(
            cfg.exclude_ipv6net,
            ExcludeIpv6Net {
                exclude_ipnets: vec![
                    Ipv6Net::from_str("::1/128").unwrap(),
                    Ipv6Net::from_str("fe80::/64").unwrap(),
                ],
                include_ipnets: Vec::new()
            }
        );

        assert_eq!(
            cfg.exclude_iftype.iftypes,
            vec![IfType::Metered]
        );
    }
}