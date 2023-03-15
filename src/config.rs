use std::str::FromStr;

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};

/// Configuration file template
pub const CLIENT_CONFIG_TEMPLATE: &str = r#"## Configuration for rqst VPN client

## Path groups
[[path-groups]]
kind = "ipv4net"
name = "localnet"
ipnet = "192.168.1.0/24"

[[path-groups]]
kind = "iftype"
name = "metered"
iftype = "metered"

[[path-groups]]
kind = "iftype"
name = "not-metered"
iftype = "not-metered"

[[tunnels]]
dscp = 0
path-group = "not-metered"

[[tunnels]]
dscp = 40
path-group = "not-metered"

[[tunnels]]
dscp = 56
path-group = "metered"

[exclude-ipv4net]
exclude-ipnets = ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
include-ipnets = ["192.168.1.0/24"]

[[exclude-iftypes]]
iftype = "metered"

"#;

fn default_ipv4net() -> Ipv4Net {
    Ipv4Net::from_str("0.0.0.0/0").unwrap()
}

fn default_ipv4nets() -> Vec<Ipv4Net> {
    Vec::new()
}

fn default_exclude_ipv4net() -> ExcludeIpv4Net {
    ExcludeIpv4Net {
        exclude_ipnets: Vec::new(),
        include_ipnets: Vec::new(),   
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

    #[serde(rename = "exclude-iftypes", default)]
    pub exclude_iftypes: Vec<ExcludeIfType>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ipv4NetPathGroup {
    name: String,
    #[serde(default = "default_ipv4net")]
    pub ipnet: Ipv4Net,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "iftype", deny_unknown_fields)]
pub enum IfTypePathGroup {
    #[serde(rename = "metered")]
    Metred {
        name: String,
    },

    #[serde(rename = "not-metered")]
    NotMetred {
        name: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum PathGroup {
    #[serde(rename = "ipv4net")]
    Ipv4Net(Ipv4NetPathGroup),
    #[serde(rename = "iftype")]
    IfType(IfTypePathGroup),
}

impl PathGroup {
    pub fn name(&self) -> &str {
        match self {
            Self::Ipv4Net(Ipv4NetPathGroup { name, ..}) => name,
            Self::IfType(IfTypePathGroup::Metred { name }) => name,
            Self::IfType(IfTypePathGroup::NotMetred { name }) => name,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tunnel {
    pub dscp: u8,
    #[serde(rename = "path-group")]
    pub path_group: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExcludeIpv4Net {
    #[serde(rename = "exclude-ipnets", default = "default_ipv4nets")]
    pub exclude_ipnets: Vec<Ipv4Net>,
    #[serde(rename = "include-ipnets", default = "default_ipv4nets")]
    pub include_ipnets: Vec<Ipv4Net>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "iftype", deny_unknown_fields)]
pub enum ExcludeIfType {
    #[serde(rename = "metered")]
    Metred,

    #[serde(rename = "not-metered")]
    NotMetred,
}

mod test {
    use super::*;

    const CLIENT_CONFIG: &str = r#"
        [[path-groups]]
        kind = "ipv4net"
        name = "localnet"
        ipnet = "192.168.1.0/24"
        [[path-groups]]
        kind = "iftype"
        name = "metered"
        iftype = "metered"
        [[path-groups]]
        kind = "iftype"
        name = "not-metered"
        iftype = "not-metered"
        [[tunnels]]
        dscp = 56
        path-group = "localnet"
        [exclude-ipv4net]
        exclude-ipnets = ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
        include-ipnets = ["192.168.1.0/24"]
        [[exclude-iftypes]]
        iftype = "metered"
    "#;

    #[test]
    fn client_config() {
        let cfg: ClientConfig = toml::from_str(CLIENT_CONFIG).unwrap();

        assert_eq!(
            cfg.path_groups,
            vec![
                PathGroup::Ipv4Net(Ipv4NetPathGroup {
                    name: "localnet".to_string(),
                    ipnet: Ipv4Net::from_str("192.168.1.0/24").unwrap(),
                }),
                PathGroup::IfType(IfTypePathGroup::Metred {
                    name: "metered".to_string(),
                }),
                PathGroup::IfType(IfTypePathGroup::NotMetred {
                    name: "not-metered".to_string(),
                })
            ]
        );

        assert_eq!(
            cfg.tunnels,
            vec![
                Tunnel {
                    dscp: 56,
                    path_group: "localnet".to_string(),
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
            cfg.exclude_iftypes,
            vec![ExcludeIfType::Metred]
        );
    }
}