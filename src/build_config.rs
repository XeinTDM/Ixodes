include!(concat!(env!("OUT_DIR"), "/build_generated.rs"));

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuildVariant {
    Alpha,
    Beta,
    Gamma,
    Delta,
}

#[cfg(build_variant = "alpha")]
pub const BUILD_VARIANT: BuildVariant = BuildVariant::Alpha;
#[cfg(build_variant = "beta")]
pub const BUILD_VARIANT: BuildVariant = BuildVariant::Beta;
#[cfg(build_variant = "gamma")]
pub const BUILD_VARIANT: BuildVariant = BuildVariant::Gamma;
#[cfg(build_variant = "delta")]
pub const BUILD_VARIANT: BuildVariant = BuildVariant::Delta;
impl BuildVariant {
    pub fn describe(&self) -> &'static str {
        match self {
            BuildVariant::Alpha => "alpha",
            BuildVariant::Beta => "beta",
            BuildVariant::Gamma => "gamma",
            BuildVariant::Delta => "delta",
        }
    }
}

pub fn task_order_key(label: &str) -> u64 {
    let mut acc = TASK_ORDER_SEED;
    for (idx, byte) in label.as_bytes().iter().enumerate() {
        let salt = TASK_ORDER_SALT[idx % TASK_ORDER_SALT.len()] as u64;
        let block = BULK_RANDOM_BLOCK[idx % BULK_RANDOM_BLOCK.len()] as u64;
        let rotated = ((u64::from(*byte) ^ salt).wrapping_mul(0x9e3779b97f4a7c15))
            .rotate_left(((idx % 63) as u32).saturating_add(1));
        acc = acc
            .wrapping_add(rotated)
            .wrapping_add(block << ((idx % 8) * 8));
    }
    acc ^ TASK_ORDER_SEED.rotate_left(label.len() as u32)
}
