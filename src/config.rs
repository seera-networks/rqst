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
dscp = 56
path-group = "metered"

"#;

fn default_ipv4net() -> Ipv4Net {
    Ipv4Net::from_str("0.0.0.0/0").unwrap()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientConfig {
    #[serde(rename = "path-groups" ,default)]
    pub path_groups: Vec<PathGroup>,

    #[serde(default)]
    pub tunnels: Vec<Tunnel>,
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
    dscp: u8,
    #[serde(rename = "path-group")]
    path_group: String,
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
    }
}