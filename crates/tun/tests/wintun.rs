#![cfg(windows)]

use concord_tun::{Prefix, TunDevice, TunOptions};

#[tokio::test]
#[ignore = "needs administrator rights and creates a wintun adapter"]
async fn the_compiled_in_wintun_creates_a_device_twice() {
    let options = TunOptions {
        device: Some("concord-wintun-probe".to_owned()),
        inet4_address: Prefix::new([198, 18, 255, 1].into(), 30)
            .into_iter()
            .collect(),
        ..TunOptions::default()
    };
    for _ in 0..2 {
        let device = TunDevice::create(&options).unwrap();
        assert_eq!(device.name(), "concord-wintun-probe");
    }
}
