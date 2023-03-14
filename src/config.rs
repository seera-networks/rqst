use std::str::FromStr;

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};

/// Configuration file template
pub const CONFIG_TEMPLATE: &str = r#"## Configuration for rqst VPN

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
pub struct Config {
    #[serde(rename = "path-groups" ,default)]
    pub path_groups: Vec<PathGroup>,

    #[serde(default)]
    pub tunnels: Vec<Tunnel>,
}

/*
impl Default for Config {
    fn default() -> Self {
        Self {
            path_groups: Vec::new(),
            tunnels: Vec::new(),
        }
    }
}
*/

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ipv4NetPathGroup {
    name: String,
    #[serde(default = "default_ipv4net")]
    ipnet: Ipv4Net,
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tunnel {
    dscp: u8,
    #[serde(rename = "path-group")]
    path_group: String,
}

mod test {
    use super::*;

    const CONFIG: &str = r#"
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
    fn values() {
        let cfg: Config = toml::from_str(CONFIG).unwrap();

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