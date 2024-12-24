fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap().as_str() == "espidf" {
        embuild::espidf::sysenv::output();
    }
}
