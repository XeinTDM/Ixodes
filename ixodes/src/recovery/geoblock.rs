use crate::recovery::helpers::obfuscation::deobf;
use crate::recovery::settings::RecoveryControl;
use serde::Deserialize;
use std::collections::HashSet;
use std::time::Duration;
use tracing::{error, info, warn};

#[derive(Deserialize)]
struct GeoResponse {
    country_code: Option<String>,
    country: Option<String>,
    #[serde(rename = "countryCode")]
    country_code_alt: Option<String>,
}

pub async fn check_geoblock() -> bool {
    let blocked_opt = RecoveryControl::global().blocked_countries();
    let blocked = match blocked_opt {
        Some(set) if !set.is_empty() => set,
        _ => return true,
    };

    match get_system_country() {
        Ok(Some(sys_code)) => {
            if is_blocked(&sys_code, blocked) {
                warn!(
                    "execution blocked by system locale settings (detected: {}, blocked_in: {:?})",
                    sys_code, blocked
                );
                return false;
            }
            info!("system locale check passed (detected: {})", sys_code);
        }
        Ok(None) => warn!("could not determine system country"),
        Err(e) => warn!("failed to check system country: {}", e),
    }

    match fetch_ip_country_code().await {
        Ok(ip_code) => {
            if is_blocked(&ip_code, blocked) {
                warn!(
                    "execution blocked by ip geolocation (detected: {}, blocked_in: {:?})",
                    ip_code, blocked
                );
                return false;
            }
            info!("ip geolocation check passed (detected: {})", ip_code);
        }
        Err(err) => {
            error!(error = %err, "all ip geolocation providers failed, proceeding based on system locale only");
        }
    }

    true
}

fn is_blocked(code: &str, blocked: &HashSet<String>) -> bool {
    let code = code.to_uppercase();
    blocked.contains(&code)
}

#[cfg(target_os = "windows")]
fn get_system_country() -> Result<Option<String>, String> {
    use windows::Win32::Globalization::{GEO_ISO2, GEOCLASS_NATION, GetGeoInfoW, GetUserGeoID};

    unsafe {
        let geo_id = GetUserGeoID(GEOCLASS_NATION);
        if geo_id == 0 {
            return Ok(None);
        }

        let len = GetGeoInfoW(geo_id, GEO_ISO2, None, 0);
        if len == 0 {
            return Ok(None);
        }

        let mut buffer = vec![0u16; len as usize];
        let result = GetGeoInfoW(geo_id, GEO_ISO2, Some(&mut buffer), 0);

        if result == 0 {
            return Err("GetGeoInfoW failed".to_string());
        }

        let s = String::from_utf16_lossy(&buffer);
        let code = s.trim_matches(char::from(0)).trim().to_uppercase();

        if code.len() == 2 {
            Ok(Some(code))
        } else {
            Ok(None)
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn get_system_country() -> Result<Option<String>, String> {
    Ok(None)
}

async fn fetch_ip_country_code() -> Result<String, String> {
    let client = crate::recovery::helpers::winhttp::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| e.to_string())?;

    let providers = [
        (
            deobf(&[
                0xD5, 0xCD, 0xCD, 0xCD, 0x87, 0x92, 0x92, 0xD4, 0xCD, 0x90, 0xDB, 0xCF, 0xD4, 0x93,
                0xD3, 0xD2, 0xD0, 0x92, 0xD3, 0xCE, 0xDA, 0x92,
            ]),
            extract_ip_api as fn(GeoResponse) -> Option<String>,
        ),
        (
            deobf(&[
                0xD5, 0xC9, 0xC9, 0xCD, 0xCE, 0x87, 0x92, 0x92, 0xD4, 0xCD, 0xC5, 0xDA, 0xD2, 0x93,
                0xD4, 0xCE, 0x92,
            ]),
            extract_ipwho_is,
        ),
        (
            deobf(&[
                0xD5, 0xC9, 0xC9, 0xCD, 0xCE, 0x87, 0x92, 0x92, 0xDC, 0xCD, 0xD4, 0x93, 0xDA, 0xD2,
                0xC8, 0xD3, 0xCD, 0xCB, 0xC4, 0x93, 0xD4, 0xCE,
            ]),
            extract_country_is,
        ),
    ];

    for (url, extractor) in providers {
        match client.get(&url).send().await {
            Ok(resp) => match resp.json::<GeoResponse>().await {
                Ok(json) => {
                    if let Some(code) = extractor(json) {
                        return Ok(code.to_uppercase());
                    }
                }
                Err(e) => warn!("failed to parse json from {}: {}", url, e),
            },
            Err(e) => warn!("failed to reach {}: {}", url, e),
        }
    }

    Err("all geolocation providers failed".to_string())
}

fn extract_ip_api(json: GeoResponse) -> Option<String> {
    json.country_code_alt
}

fn extract_ipwho_is(json: GeoResponse) -> Option<String> {
    json.country_code
}

fn extract_country_is(json: GeoResponse) -> Option<String> {
    json.country
}
