pub fn map_to_new_oid(oid: &str) -> String {
    match oid {
        // ML-DSA IPD to NIST
        "1.3.6.1.4.1.2.267.12.4.4" => "2.16.840.1.101.3.4.3.17",
        "1.3.6.1.4.1.2.267.12.6.5" => "2.16.840.1.101.3.4.3.18",
        "1.3.6.1.4.1.2.267.12.8.7" => "2.16.840.1.101.3.4.3.19",
        // ML-KEM IPD to NIST
        "1.3.6.1.4.1.22554.5.6.1" => "2.16.840.1.101.3.4.4.1",
        "1.3.6.1.4.1.22554.5.6.2" => "2.16.840.1.101.3.4.4.2",
        "1.3.6.1.4.1.22554.5.6.3" => "2.16.840.1.101.3.4.4.3",
        _ => oid,
    }
    .to_string()
}
