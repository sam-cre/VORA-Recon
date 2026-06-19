use serde::Deserialize;
use std::net::IpAddr;
use std::sync::mpsc;
use std::thread;

#[derive(Clone, Debug)]
pub struct GeoInfo {
    pub country_code: String,
    pub city: Option<String>,
    pub region: Option<String>,
    pub org: String,
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct IpApiResponse {
    status: String,
    countryCode: Option<String>,
    region: Option<String>,
    city: Option<String>,
    org: Option<String>,
}

pub fn start_geo_thread(
    req_rx: mpsc::Receiver<IpAddr>,
    res_tx: mpsc::Sender<(IpAddr, Option<GeoInfo>)>,
) {
    thread::spawn(move || {
        // Iterate blocking on incoming IP requests
        for ip in req_rx {
            let url = format!("http://ip-api.com/json/{}?fields=status,countryCode,region,city,org", ip);
            
            let result = ureq::get(&url)
                .timeout(std::time::Duration::from_secs(3))
                .call();

            match result {
                Ok(response) => {
                    if let Ok(data) = response.into_json::<IpApiResponse>() {
                        if data.status == "success" {
                            // Strip control chars from API response fields — a MITM on the
                            // plaintext HTTP connection could inject ANSI sequences otherwise.
                            let clean = |s: String| s.chars().filter(|c| !c.is_control()).collect::<String>();
                            let country = data.countryCode.map(clean).unwrap_or_else(|| "??".to_string());
                            // Validate country code is 2 ASCII letters; reject anything else
                            let country = if country.len() == 2 && country.chars().all(|c| c.is_ascii_alphabetic()) {
                                country
                            } else {
                                "??".to_string()
                            };
                            let info = GeoInfo {
                                country_code: country,
                                city: data.city.map(|s| s.chars().filter(|c| !c.is_control()).collect()),
                                region: data.region.map(|s| s.chars().filter(|c| !c.is_control()).collect()),
                                org: data.org.map(|s| s.chars().filter(|c| !c.is_control()).collect::<String>())
                                    .filter(|s| !s.is_empty())
                                    .unwrap_or_else(|| "Unknown".to_string()),
                            };
                            let _ = res_tx.send((ip, Some(info)));
                        } else {
                            let _ = res_tx.send((ip, None));
                        }
                    } else {
                        let _ = res_tx.send((ip, None));
                    }
                }
                Err(_) => {
                    // Fail gracefully on internet access loss / timeout
                    let _ = res_tx.send((ip, None));
                }
            }

            // Respect free API limits (45 req / minute => ~1.33 seconds per req)
            // By doing sequential blocking we rate limit naturally, but a short sleep is kind
            thread::sleep(std::time::Duration::from_millis(200));
        }
    });
}
