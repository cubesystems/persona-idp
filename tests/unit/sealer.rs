use std::time::Duration;

use persona_idp::sealer::{Purpose, Sealer};

const LIFETIME: Duration = Duration::from_secs(60);

#[test]
fn opens_what_it_sealed() {
    let sealer = Sealer::new();
    let token = sealer
        .seal(Purpose::Code, &"payload".to_string(), LIFETIME)
        .unwrap();

    assert_eq!(
        sealer.open::<String>(Purpose::Code, &token).as_deref(),
        Some("payload")
    );
}

#[test]
fn refuses_a_token_sealed_for_another_purpose() {
    let sealer = Sealer::new();
    let token = sealer
        .seal(Purpose::UpstreamState, &"payload".to_string(), LIFETIME)
        .unwrap();

    assert!(sealer.open::<String>(Purpose::Picker, &token).is_none());
}

#[test]
fn refuses_an_expired_token() {
    let sealer = Sealer::new();
    let token = sealer
        .seal(Purpose::Code, &"payload".to_string(), Duration::ZERO)
        .unwrap();
    std::thread::sleep(Duration::from_millis(1100));

    assert!(sealer.open::<String>(Purpose::Code, &token).is_none());
}

#[test]
fn refuses_a_token_from_another_sealer() {
    let token = Sealer::new()
        .seal(Purpose::Code, &"payload".to_string(), LIFETIME)
        .unwrap();

    assert!(
        Sealer::new()
            .open::<String>(Purpose::Code, &token)
            .is_none()
    );
}

#[test]
fn refuses_a_tampered_or_truncated_token() {
    let sealer = Sealer::new();
    let token = sealer
        .seal(Purpose::Code, &"payload".to_string(), LIFETIME)
        .unwrap();

    assert!(
        sealer
            .open::<String>(Purpose::Code, &format!("{token}x"))
            .is_none()
    );
    assert!(sealer.open::<String>(Purpose::Code, "short").is_none());
}
