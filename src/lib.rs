use failure::{self, Fail, ResultExt};
use hyper::header::{Cookie, Headers};
use std::str::FromStr;
pub type Result<T> = std::result::Result<T, failure::Error>;
use hmacsha1::hmac_sha1;
use time;

pub fn hex(bytes: &[u8]) -> String {
    let strs: Vec<String> = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    strs.join("")
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, Fail)]
pub enum ClientErrorKind {
    // A plain enum with no data in any of its variants
    //
    #[fail(display = "Cookie not found")]
    CookieNotFound,

    #[fail(display = "Value error")]
    ValueError,

    #[fail(display = "Signature is invalid")]
    InvalidSignature,

    #[fail(display = "Signed cookie expired")]
    SignedCookieExpired,
}

pub fn signed_cookie<T: FromStr>(
    headers: &Headers,
    name: &str,
    signature_life: i64,
    cookie_secret_key: &str,
) -> Result<T> {
    let cookie = headers
        .get::<Cookie>()
        .and_then(|c| c.get(name))
        .map(|c| c.to_owned())
        .ok_or(ClientErrorKind::CookieNotFound)?;

    signed_value(
        &cookie,
        signature_life,
        &cookie_secret_key.to_string().as_bytes().to_vec(),
    )
}

pub fn signed_value<T: FromStr>(
    value: &str,
    signature_life: i64,
    cookie_secret_key_bytes: &Vec<u8>,
) -> Result<T> {
    let parts = value.split(":").collect::<Vec<_>>();
    if parts.len() != 3 {
        return Err(ClientErrorKind::ValueError)
            .context(format!("not enough parts: found {}", parts.len()))?;
    }

    let (c, t, s) = (parts[0], parts[1], parts[2]);
    let candidate = format!("{}:{}", c, t);
    let delta = time::get_time().sec - t.parse::<i64>().unwrap_or(0);
    if delta > signature_life {
        return Err(ClientErrorKind::ValueError)
            .context(format!("timestamp too old: {}", delta,))?;
    }

    let expected = hex(&hmac_sha1(&cookie_secret_key_bytes, candidate.as_bytes()));
    if s != expected {
        return Err(ClientErrorKind::InvalidSignature).context(format!(
            "signature doesnt match, expected: {}, found: {}",
            expected, s
        ))?;
    }

    match c.parse::<T>() {
        Ok(t) => Ok(t),
        Err(_) => Err(ClientErrorKind::ValueError).context(format!("failed to parse"))?,
    }
}

pub fn sign_value(value: &str, uat_cookie_secret_bytes: &Vec<u8>) -> String {
    let value = format!("{}:{}", value, time::get_time().sec);
    let signature = hex(&hmac_sha1(&uat_cookie_secret_bytes, value.as_bytes()));
    format!("{}:{}", value, signature)
}

#[cfg(test)]
mod tests {
    use super::{sign_value, signed_value};
    #[test]
    fn it_works() {
        let secret = "foo_secret";
        let secret_bytes = secret.to_string().as_bytes().to_vec();
        assert_eq!(
            signed_value::<String>(&sign_value("foo", &secret_bytes), 3600, &secret_bytes).unwrap(),
            "foo"
        );
    }
}
