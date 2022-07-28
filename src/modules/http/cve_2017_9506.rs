/// # CVE-2017-9606 Detail
/// - Infotecs ViPNet Client and Coordinator before 4.3.2-42442 allow local users to gain privileges by
/// placing a Trojan horse ViPNet update file in the update folder.
/// - The attack succeeds because of incorrect folder permissions in conjunction with a lack of integrity and
/// authenticity checks.

use crate::{
	modules::{HttpFinding, HttpModule, Module},
	Error,
};
use async_trait::async_trait;
use reqwest::Client;

pub struct Cve2017_9506 {}

impl Cve2017_9506 {
	pub fn new() -> Self {
		Cve2017_9506 {}
	}
}

impl Module for Cve2017_9506 {
	fn name(&self) -> String {
		String::from("http/cve_2017_9506")
	}
	
	fn description(&self) -> String {
		String::from("Check for CVE-2017-9506 (SSRF)")  // server-side request forgery
	}
}

#[async_trait]
impl HttpModule for Cve2017_9506 {
	async fn scan(&self, http_client: &Client, endpoint: &str) -> Result<Option<HttpFinding>, Error> {
		// create a robot.txt crawler
		let url = format!(
			"{}/plugins/servlet/oauth/users/icon-uri?consumerUri=https://google.com/robots.txt",
			&endpoint
		);
		let res = http_client.get(&url).send().await?;
		
		if !res.status().is_success() {
			return Ok(None);
		}
		
		let body = res.text().await?;
		if body.contains("user-agent: *") && body.contains("disallow") {
			return Ok(Some(HttpFinding::Cve2017_9506(url)));
		}
		
		Ok(None)
	}
}

