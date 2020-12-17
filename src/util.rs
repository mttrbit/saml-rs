use {
    regex::Regex,
    reqwest::{blocking::Response, header::HeaderMap, StatusCode},
};

pub fn parse_redirect_url(url: &str) -> Option<Vec<&str>> {
    let re = Regex::new(r#"(\w*).{3}([\w\-\.]*):?(\d*)?(/\S*)\?"#).unwrap();

    match re.captures(url) {
        Some(caps) => {
            let mut parts = Vec::new();

            if caps.len() > 1 {
                for c in caps.iter().skip(1) {
                    parts.push(c.unwrap().as_str());
                }

                Some(parts)
            } else {
                None
            }
        }
        _ => None,
    }
}

pub fn to_result(res: Response) -> crate::Result<(HeaderMap, StatusCode, Option<String>)> {
    let headers = res.headers().clone();
    let status = StatusCode::from(res.status());
    Ok((headers, status, Some(res.text()?)))
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn test_parse_redirect_url_with_port() {
        let url = "https://some-domain-prod.example.com:8890/adfs/ls?SAMLRequest=jZJPTwIxEMW/yqb37nb/gNIACYpREgQC6MGL6XZnoUm3XTtd4se3AiZwIR6nM7837006RNHolk86vzdr%2BOoAffTdaIP82BiRzhluBSrkRjSA3Eu%2BmbzOeRYz3jrrrbSaXCC3CYEIzitrSDSbjshy8TRfPs8Wn%2BVdUbKs16fQFxUt8vuclgOZ0qoc1EVd5nlaZCR6B4eBHZEgFQQQO5gZ9ML48MQyRtOMpmzLBpzlvMc%2BSDQNeZQR/kjtvW%2BRJ4m0rqXokQb/VXywlaitgVjaJhFVjYlGEq3O0R6UqZTZ3U5VnoaQv2y3K7pabrYkmvwlfbQGuwbcBtxBSXhbzy%2BctBjWmlp3YCTEYqc0XBtqdbdTBpMgdtDgk98Ty7MiGQ9/S348hBv/W3SYXGKn6voLjH8A&RelayState=e8bf4188-3c71-4d01-b4d0-083d9aac24d6";
        let res = parse_redirect_url(url);
        assert_eq!(4, res.unwrap().len());
    }

    #[test]
    fn test_parse_redirect_url() {
        let url = "https://some-domain-prod.example.com/adfs/ls?SAMLRequest=jZJPTwIxEMW/yqb37nb/gNIACYpREgQC6MGL6XZnoUm3XTtd4se3AiZwIR6nM7837006RNHolk86vzdr%2BOoAffTdaIP82BiRzhluBSrkRjSA3Eu%2BmbzOeRYz3jrrrbSaXCC3CYEIzitrSDSbjshy8TRfPs8Wn%2BVdUbKs16fQFxUt8vuclgOZ0qoc1EVd5nlaZCR6B4eBHZEgFQQQO5gZ9ML48MQyRtOMpmzLBpzlvMc%2BSDQNeZQR/kjtvW%2BRJ4m0rqXokQb/VXywlaitgVjaJhFVjYlGEq3O0R6UqZTZ3U5VnoaQv2y3K7pabrYkmvwlfbQGuwbcBtxBSXhbzy%2BctBjWmlp3YCTEYqc0XBtqdbdTBpMgdtDgk98Ty7MiGQ9/S348hBv/W3SYXGKn6voLjH8A&RelayState=e8bf4188-3c71-4d01-b4d0-083d9aac24d6";
        let res = parse_redirect_url(url);
        assert_eq!(3, res.unwrap().len());
    }
}
