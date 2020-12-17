use {
    crate::util::{parse_redirect_url, to_result},
    lazy_static::lazy_static,
    rand::distributions::Alphanumeric,
    rand::{thread_rng, Rng},
    regex::Regex,
    reqwest::{blocking::Client, header, header::HeaderMap, StatusCode},
    serde::Deserialize,
    std::rc::Rc,
    vip::vip::fetch_security_code,
};

mod util;

lazy_static! {
    pub static ref SAMLRESPONSE_RE: Regex =
       Regex::new(
            r#"action="(.*)">.*name="SAMLResponse" value="([a-zA-Z0-9+=\-_]*)".*name="RelayState" value="([a-zA-Z0-9\-]*)""#
        )
        .unwrap();

    pub static ref REDIRECT_RE: Regex =
        Regex::new(r#"window.location.assign\("(.*)"\)"#).unwrap();

    pub static ref LOGIN_RE: Regex =
        Regex::new(
            r#"Context"\svalue="(\S+)"[\s\S]*AuthMethod"\svalue="(\S+)"[\s\S]*pass\.value\s=\s(\S+)";[\s\S]*action="(\S+)""#
        ).unwrap();

    pub static ref ACTION_RE: Regex = Regex::new(r#"action="(.*)""#).unwrap();
}

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;

#[derive(Deserialize, Debug)]
pub struct SAMLResponse {
    pub url: String,
    pub saml_response: String,
    pub relay_state: String,
}

impl From<String> for SAMLResponse {
    fn from(html: String) -> Self {
        let cap = SAMLRESPONSE_RE.captures(&html).unwrap();
        Self {
            url: cap[1].to_string(),
            saml_response: cap[2].to_string(),
            relay_state: cap[3].to_string(),
        }
    }
}

#[derive(Deserialize, Debug)]
pub struct SAMLRequest {
    pub url: String,
    pub context: String,
    pub vippassword: String,
    pub auth_method: String,
    pub security_code: String,
}

impl SAMLRequest {
    pub fn security_code_mut(&mut self) -> &mut String {
        &mut self.security_code
    }
}

impl<'g> From<String> for SAMLRequest {
    fn from(html: String) -> Self {
        let cap = LOGIN_RE.captures(&html).unwrap();
        Self {
            url: cap[4].to_string(),
            context: cap[1].to_string(),
            vippassword: cap[3].to_string(),
            auth_method: cap[2].to_string(),
            security_code: "".to_string(),
        }
    }
}

pub struct RedirectResponse {
    html: String,
    host: String,
}

impl RedirectResponse {
    fn new(html: &str, host: &str) -> Self {
        Self {
            html: html.to_string(),
            host: host.to_string(),
        }
    }
}

fn parse_redirect_url_to_login(html: &str) -> Result<String> {
    match REDIRECT_RE.captures(&html) {
        Some(cap) => Ok(cap[1].to_string()),
        _ => Err("Could not parse redirect url to login page".into()),
    }
}

pub struct IdP {
    pub(crate) client: Rc<Client>,
}

impl IdP {
    pub fn with_client(client: &Rc<Client>) -> Self {
        Self {
            client: client.clone(),
        }
    }

    fn call(
        &self,
        url: &str,
        params: &[(&str, &str)],
    ) -> Result<(HeaderMap, StatusCode, Option<String>)> {
        let request = self
            .client
            .post(url)
            .header(
                header::USER_AGENT,
                header::HeaderValue::from_static(
                    "Mozilla/5.0 (Windows NT 6.1; rv:52.0) Gecko/20100101 Firefox/52.0",
                ),
            )
            .form(&params)
            .build()?;

        match self.client.execute(request) {
            Ok(res) => {
                let headers = res.headers().clone();
                let status = StatusCode::from(res.status());
                Ok((headers, status, Some(res.text()?)))
            }
            Err(e) => Err(e.into()),
        }
    }

    fn open_login_page(
        &self,
        url: &str,
    ) -> Result<(HeaderMap, StatusCode, Option<RedirectResponse>)> {
        match self.client.get(url).send().and_then(|res| {
            let (h, s, html) = to_result(res).unwrap();
            let parts: Vec<&str> = parse_redirect_url(&url).unwrap();
            Ok((
                h,
                s,
                Some(RedirectResponse::new(
                    &html.unwrap(),
                    &format!("{}://{}", parts[0], parts[1]),
                )),
            ))
        }) {
            Ok((h, s, data)) => Ok((h, s, data)),
            Err(e) => Err(e.into()),
        }
    }

    fn parse_form_action_endpoint(&self, html: &str) -> Result<String> {
        if let Ok(re) = Regex::new(r#"action="(.*)""#) {
            if let Some(cap) = re.captures(&html) {
                return Ok(cap[1].to_string());
            }
        }

        Err("Could not parse form action url".into())
    }

    fn login(
        &self,
        url: &str,
        username: &str,
        password: &str,
    ) -> Result<(HeaderMap, StatusCode, Option<SAMLRequest>)> {
        let params = [
            ("UserName", username),
            ("Password", password),
            ("AuthMethod", &"FormsAuthentication".to_string()),
        ];

        self.call(&url, &params)
            .and_then(|(h, s, body)| Ok((h, s, Some(SAMLRequest::from(body.unwrap())))))
    }

    // auth_method: VIPAuthenticationProviderUPN
    fn send_saml_request(
        &self,
        username: &str,
        ctx: &SAMLRequest,
    ) -> Result<(HeaderMap, StatusCode, Option<SAMLResponse>)> {
        let params = [
            ("username", username),
            ("vippassword", &ctx.vippassword),
            ("security_code", &ctx.security_code),
            ("Context", &ctx.context),
            ("AuthMethod", &ctx.auth_method),
        ];

        self.call(&ctx.url, &params)
            .and_then(|(h, s, body)| Ok((h, s, Some(SAMLResponse::from(body.unwrap())))))
    }

    fn send_saml_response(
        &self,
        saml: &SAMLResponse,
    ) -> Result<(HeaderMap, StatusCode, Option<String>)> {
        let params = [
            ("SAMLResponse", saml.saml_response.as_str()),
            ("RelayState", saml.relay_state.as_str()),
        ];

        self.call(&saml.url, &params)
    }

    pub fn authenticate(&self, url: &str, user: &str, password: &str) -> Result<()> {
        let open_page: reqwest::blocking::Response = self.client.get(url).send()?;

        let apply_auth_method = |mut context: SAMLRequest| -> Result<SAMLRequest> {
            let parts = parse_redirect_url(&context.url).unwrap();
            let request_id: String = thread_rng().sample_iter(&Alphanumeric).take(30).collect();
            let response = fetch_security_code(
                &user.replace("@", "%40"),
                &request_id,
                &format!("{}://{}", parts[0], parts[1]),
            )?;
            *context.security_code_mut() = response.ret.ticket;
            Ok(context)
        };

        let build_form_action_url = |maybe_data: Option<RedirectResponse>| -> Result<String> {
            match maybe_data {
                Some(d) => Ok([d.host, self.parse_form_action_endpoint(&d.html)?].concat()),
                _ => Err("Could not build form action url".into()),
            }
        };

        if url == open_page.url().to_string() {
            Ok({})
        } else {
            parse_redirect_url_to_login(&open_page.text()?)
                .map(|url| self.open_login_page(&url))?
                .map(|(_, _, data)| build_form_action_url(data))?
                .map(|url| self.login(&url, user, password))?
                .map(|(_, _, d)| apply_auth_method(d.unwrap()))?
                .map(|ctx| self.send_saml_request(user, &ctx))? // it appears the username is irrelevant
                .map(|(_, _, d)| self.send_saml_response(&d.unwrap()))?
                .map(|_| {})
        }
    }
}
