use tokio::io::{AsyncWriteExt, DuplexStream, duplex};

use super::*;
use crate::FramedChannel;
use concord_rpc::{Incoming, MessageChannel, MessageReader, MessageWriter};

const TOKEN: &str = "0123456789abcdef0123456789abcdef";
const OTHER: &str = "fedcba9876543210fedcba9876543210";

fn token(text: &str) -> Token {
    Token::parse(text).unwrap()
}

fn pair() -> (DuplexStream, DuplexStream) {
    duplex(4096)
}

#[test]
fn a_token_is_32_lowercase_hex_digits() {
    assert!(Token::parse(TOKEN).is_ok());
    for bad in [
        "",
        "0123",
        &TOKEN.to_uppercase(),
        &TOKEN[..31],
        &format!("{TOKEN}0"),
        "0123456789abcdef0123456789abcdeg",
        " 123456789abcdef0123456789abcdef",
    ] {
        assert!(
            matches!(Token::parse(bad), Err(AuthError::BadToken)),
            "{bad}"
        );
    }
}

#[test]
fn a_token_does_not_print() {
    assert!(!format!("{:?}", token(TOKEN)).contains("0123"));
}

#[tokio::test]
async fn matching_tokens_authenticate_and_frames_flow_afterwards() {
    let (mut near, mut far) = pair();
    let (good, same) = (token(TOKEN), token(TOKEN));
    let (initiated, responded) = tokio::join!(initiate(&mut near, &good), respond(&mut far, &same));
    initiated.unwrap();
    responded.unwrap();

    let (_, mut write) = FramedChannel::new(near).split();
    let (mut read, _) = FramedChannel::new(far).split();
    write.send(b"after".to_vec()).await.ok().unwrap();
    assert_eq!(
        read.recv().await.unwrap(),
        Some(Incoming::Message(b"after".to_vec()))
    );
}

#[tokio::test]
async fn a_responder_with_another_token_is_rejected_by_the_initiator() {
    let (mut near, mut far) = pair();
    let (good, other) = (token(TOKEN), token(OTHER));
    let (initiated, responded) = tokio::join!(
        async {
            let result = initiate(&mut near, &good).await;
            drop(near);
            result
        },
        respond(&mut far, &other),
    );

    assert!(matches!(initiated, Err(AuthError::Rejected)));
    assert!(responded.is_err());
}

#[tokio::test]
async fn an_initiator_with_another_token_is_rejected_by_the_responder() {
    let (mut near, mut far) = pair();
    let (good, other) = (token(TOKEN), token(OTHER));
    let (initiated, responded) = tokio::join!(
        async {
            let ours = nonce();
            send(&mut near, &ours).await.unwrap();
            let reply = receive(&mut near, NONCE_LEN + PROOF_LEN).await.unwrap();
            let forged = proof(&other, Role::Initiator, &ours, &reply[..NONCE_LEN]);
            send(&mut near, &forged).await
        },
        respond(&mut far, &good),
    );

    initiated.unwrap();
    assert!(matches!(responded, Err(AuthError::Rejected)));
}

#[tokio::test]
async fn the_initiator_sends_no_proof_to_a_responder_that_failed() {
    let (mut near, mut far) = pair();
    let initiating = tokio::spawn(async move { initiate(&mut near, &token(TOKEN)).await });

    let nonce_frame = receive(&mut far, NONCE_LEN).await.unwrap();
    assert_eq!(nonce_frame.len(), NONCE_LEN);
    let mut reply = vec![0u8; NONCE_LEN + PROOF_LEN];
    reply[..NONCE_LEN].copy_from_slice(&nonce());
    send(&mut far, &reply).await.unwrap();

    assert!(matches!(
        initiating.await.unwrap(),
        Err(AuthError::Rejected)
    ));
    let mut rest = Vec::new();
    far.shutdown().await.unwrap();
    far.read_to_end(&mut rest).await.unwrap();
    assert!(
        rest.is_empty(),
        "the initiator sent {} more bytes",
        rest.len()
    );
}

#[tokio::test(start_paused = true)]
async fn a_responder_that_never_answers_times_out() {
    let (mut near, _far) = pair();

    let result = initiate(&mut near, &token(TOKEN)).await;

    assert!(matches!(result, Err(AuthError::Timeout)));
}

#[tokio::test(start_paused = true)]
async fn an_initiator_that_never_speaks_times_out() {
    let (_near, mut far) = pair();

    let result = respond(&mut far, &token(TOKEN)).await;

    assert!(matches!(result, Err(AuthError::Timeout)));
}

#[tokio::test]
async fn a_peer_that_closes_without_answering_fails_the_handshake() {
    let (mut near, far) = pair();
    drop(far);

    let result = initiate(&mut near, &token(TOKEN)).await;

    assert!(matches!(result, Err(AuthError::Io(_))));
}

#[tokio::test]
async fn garbage_is_malformed_and_a_huge_length_is_not_read() {
    let (mut near, mut far) = pair();
    far.write_all(&u32::MAX.to_le_bytes()).await.unwrap();

    let result = initiate(&mut near, &token(TOKEN)).await;

    assert!(matches!(result, Err(AuthError::Malformed)));

    let (mut near, mut far) = pair();
    far.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
    assert!(matches!(
        respond(&mut near, &token(TOKEN)).await,
        Err(AuthError::Malformed)
    ));
}

#[tokio::test]
async fn an_echo_of_the_initiators_own_frame_is_not_a_responder() {
    let (mut near, far) = pair();
    let (mut echo_read, mut echo_write) = tokio::io::split(far);
    let echoing = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut echo_read, &mut echo_write).await;
    });

    let result = initiate(&mut near, &token(TOKEN)).await;

    assert!(matches!(result, Err(AuthError::Malformed)));
    drop(near);
    echoing.await.unwrap();
}

#[test]
fn a_proof_is_bound_to_its_role_and_both_nonces() {
    let token = token(TOKEN);
    let (a, b) = ([1u8; NONCE_LEN], [2u8; NONCE_LEN]);

    let initiator = proof(&token, Role::Initiator, &a, &b);

    assert_ne!(initiator, proof(&token, Role::Responder, &a, &b));
    assert_ne!(initiator, proof(&token, Role::Initiator, &b, &a));
    assert_ne!(
        initiator,
        proof(&token, Role::Initiator, &a, &[3u8; NONCE_LEN])
    );
    assert_ne!(
        initiator,
        proof(
            &super::Token::parse(OTHER).unwrap(),
            Role::Initiator,
            &a,
            &b
        )
    );
}

#[tokio::test]
async fn nothing_on_the_wire_contains_the_token() {
    let (mut near, mut far) = pair();
    let tap = tokio::spawn(async move {
        let mut seen = Vec::new();
        let mut buffer = [0u8; 256];
        loop {
            let count = far.read(&mut buffer).await.unwrap();
            if count == 0 {
                return seen;
            }
            seen.extend_from_slice(&buffer[..count]);
            if seen.len() == 4 + NONCE_LEN {
                let mut reply = vec![0u8; NONCE_LEN + PROOF_LEN];
                reply[..NONCE_LEN].copy_from_slice(&[9u8; NONCE_LEN]);
                send(&mut far, &reply).await.unwrap();
            }
        }
    });

    let _ = initiate(&mut near, &token(TOKEN)).await;
    drop(near);
    let seen = tap.await.unwrap();

    assert!(
        !seen
            .windows(TOKEN.len())
            .any(|window| window == TOKEN.as_bytes())
    );
}

#[tokio::test]
async fn every_handshake_starts_with_a_fresh_nonce() {
    let mut firsts = Vec::new();
    for _ in 0..4 {
        let (mut near, mut far) = pair();
        let initiating = tokio::spawn(async move {
            let _ = initiate(&mut near, &token(TOKEN)).await;
        });
        firsts.push(receive(&mut far, NONCE_LEN).await.unwrap());
        drop(far);
        initiating.await.unwrap();
    }

    firsts.sort();
    firsts.dedup();
    assert_eq!(firsts.len(), 4);
}

/// The same vector is pinned in the Dart tests (`test/core/desktop/ipc_auth_test.dart`).
#[test]
fn proofs_match_the_vector_the_dart_host_pins() {
    let token = token(TOKEN);
    let initiator: Vec<u8> = (1..=16).collect();
    let responder: Vec<u8> = (17..=32).collect();

    let hex = |proof: Proof| {
        proof
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };

    assert_eq!(
        hex(proof(&token, Role::Initiator, &initiator, &responder)),
        "4c1b89365b44dc2258ad724caeb98ec37695a565e62e82b5ccc57574d95be7a7"
    );
    assert_eq!(
        hex(proof(&token, Role::Responder, &initiator, &responder)),
        "0e9ebf29efd273e966ce128e3f6adb19a7e52b419e7c32a3d21c940e145fa56f"
    );
}
