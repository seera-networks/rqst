#[cfg(unix)]
mod unix;
#[cfg(unix)]
use self::unix::*;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
use self::windows::*;

use anyhow::{anyhow, Context};
use if_watch::{IfEvent, IfWatcher};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use std::collections::HashSet;
use std::pin::Pin;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum IfEventExt {
    Up((IpNet, bool)),
    Down(IpNet),
}

pub struct IfWatcherExt {
    inner: IfWatcher,
    exclude_ipnets: Vec<IpNet>,
    include_ipnets: Vec<IpNet>,
    exclude_metered: bool,
    exclude_not_metered: bool,
    excluded: HashSet<IpNet>,
}

impl IfWatcherExt {
    pub async fn new(
        exclude_ipnets: Vec<IpNet>,
        include_ipnets: Vec<IpNet>,
        exclude_metered: bool,
        exclude_not_metered: bool,
    ) -> anyhow::Result<Self> {
        let ifwatcher = IfWatcher::new().await.context("initialize IfWatcher")?;
        Ok(IfWatcherExt {
            inner: ifwatcher,
            exclude_ipnets,
            include_ipnets,
            exclude_metered,
            exclude_not_metered,
            excluded: HashSet::new(),
        })
    }

    pub fn iter(&self) -> impl Iterator<Item = &IpNet> {
        self.inner.iter()
    }

    // Not cancel-safe
    pub async fn pop(&mut self) -> anyhow::Result<IfEventExt> {
        loop {
            let event = Pin::new(&mut self.inner)
                .await
                .context("IfWatcher")?;
            match event {
                IfEvent::Up(ipnet) => {
                    let excluded = self.exclude_ipnets
                        .iter()
                        .find(|exclude| {
                            exclude.contains(&ipnet)
                        });
                    let included = self.include_ipnets
                        .iter()
                        .find(|include| {
                            include.contains(&ipnet)
                        });

                    if excluded.is_none() || included.is_some() {
                        let metered = is_metered(ipnet.addr())
                            .await
                            .context("is_metered()");
                        let metered = metered?;
                        if (metered && !self.exclude_metered) ||
                            (!metered && !self.exclude_not_metered) {
                            return Ok(IfEventExt::Up((ipnet, metered)));
                        }
                    }
                    self.excluded.insert(ipnet); 
                }
                IfEvent::Down(ipnet) => {
                    if self.excluded.contains(&ipnet) {
                        self.excluded.remove(&ipnet);
                    }
                    return Ok(IfEventExt::Down(ipnet));
                }
            }
        }
    }
}
