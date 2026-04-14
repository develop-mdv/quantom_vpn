use std::time::{Duration, Instant};

use omega_core_wire::{
    AckFrame, AckRange, ConnectionId, ControlFrame, ControlKind, TrafficClass, TransportFrame,
};

use super::{PathMode, TransportConfig, TransportEndpoint};

#[test]
fn transport_reassembles_fragmented_message() {
    let mut sender = TransportEndpoint::new(
        ConnectionId([1u8; 8]),
        [9u8; 32],
        TransportConfig {
            max_datagram_payload: 96,
            ..TransportConfig::default()
        },
    );
    let now = Instant::now();
    let payload = vec![0xAB; 180];
    sender.queue_message(TrafficClass::Interactive, payload.clone());

    let first = sender.poll_datagram(now, 96).unwrap();
    let second = sender
        .poll_datagram(now + Duration::from_millis(20), 96)
        .unwrap();
    let third = sender
        .poll_datagram(now + Duration::from_millis(40), 96)
        .unwrap();

    let mut receiver = TransportEndpoint::new(
        ConnectionId([1u8; 8]),
        [9u8; 32],
        TransportConfig::default(),
    );
    assert!(receiver
        .on_datagram_received(now, first.packet_number, &first.frames)
        .is_empty());
    assert!(receiver
        .on_datagram_received(
            now + Duration::from_millis(20),
            second.packet_number,
            &second.frames
        )
        .is_empty());
    let messages = receiver.on_datagram_received(
        now + Duration::from_millis(40),
        third.packet_number,
        &third.frames,
    );
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].payload, payload);
}

#[test]
fn ack_processing_reduces_bytes_in_flight() {
    let mut sender = TransportEndpoint::new(
        ConnectionId([2u8; 8]),
        [7u8; 32],
        TransportConfig::default(),
    );
    let now = Instant::now();
    sender.queue_message(TrafficClass::Interactive, vec![1u8; 64]);
    let first = sender.poll_datagram(now, 256).unwrap();
    assert!(sender.snapshot().bytes_in_flight > 0);

    let ack = AckFrame::normalized(
        vec![AckRange::new(first.packet_number, first.packet_number)],
        1_000,
    );
    sender.on_datagram_received(
        now + Duration::from_millis(10),
        10,
        &[TransportFrame::Ack(ack)],
    );
    assert_eq!(sender.snapshot().bytes_in_flight, 0);
}

#[test]
fn out_of_order_delivery_produces_ack_ranges() {
    let mut receiver = TransportEndpoint::new(
        ConnectionId([3u8; 8]),
        [5u8; 32],
        TransportConfig::default(),
    );
    let now = Instant::now();
    receiver.on_datagram_received(
        now,
        10,
        &[TransportFrame::Control(ControlFrame {
            kind: ControlKind::KeepAlive,
            data: Vec::new(),
        })],
    );
    receiver.on_datagram_received(
        now + Duration::from_millis(1),
        12,
        &[TransportFrame::Control(ControlFrame {
            kind: ControlKind::KeepAlive,
            data: Vec::new(),
        })],
    );
    let ack = receiver
        .poll_datagram(now + Duration::from_millis(20), 128)
        .unwrap();
    let ack_frame = ack
        .frames
        .into_iter()
        .find_map(|frame| match frame {
            TransportFrame::Ack(ack) => Some(ack),
            _ => None,
        })
        .unwrap();
    assert_eq!(ack_frame.ranges.len(), 2);
    assert!(ack_frame.acks_packet(10));
    assert!(ack_frame.acks_packet(12));
    assert!(!ack_frame.acks_packet(11));
}

#[test]
fn interactive_traffic_preempts_bulk() {
    let mut endpoint = TransportEndpoint::new(
        ConnectionId([4u8; 8]),
        [3u8; 32],
        TransportConfig::default(),
    );
    endpoint.queue_message(TrafficClass::Bulk, vec![0x22; 512]);
    endpoint.queue_message(TrafficClass::Interactive, vec![0x11; 64]);
    let datagram = endpoint.poll_datagram(Instant::now(), 256).unwrap();
    assert_eq!(datagram.principal_class, TrafficClass::Interactive);
}

#[test]
fn packet_loss_requeues_once_for_retransmission() {
    let mut endpoint = TransportEndpoint::new(
        ConnectionId([5u8; 8]),
        [4u8; 32],
        TransportConfig::default(),
    );
    let now = Instant::now();
    endpoint.queue_message(TrafficClass::Interactive, vec![0x42; 64]);
    let first = endpoint.poll_datagram(now, 96).unwrap();
    let retransmit = endpoint
        .poll_datagram(now + Duration::from_millis(200), 256)
        .unwrap();
    assert_ne!(retransmit.packet_number, first.packet_number);
    let first_data = first
        .frames
        .iter()
        .find_map(|frame| match frame {
            TransportFrame::Data(data) => Some(data.payload.clone()),
            _ => None,
        })
        .unwrap();
    let retransmit_data = retransmit
        .frames
        .iter()
        .find_map(|frame| match frame {
            TransportFrame::Data(data) => Some(data.payload.clone()),
            _ => None,
        })
        .unwrap();
    assert_eq!(first_data, retransmit_data);
}

#[test]
fn connection_id_rotates_after_interval() {
    let mut endpoint = TransportEndpoint::new(
        ConnectionId([6u8; 8]),
        [5u8; 32],
        TransportConfig {
            connection_id_rotation_interval_packets: 2,
            ..TransportConfig::default()
        },
    );
    let now = Instant::now();
    endpoint.queue_message(TrafficClass::Interactive, vec![1u8; 64]);
    endpoint.queue_message(TrafficClass::Interactive, vec![2u8; 64]);
    endpoint.queue_message(TrafficClass::Interactive, vec![3u8; 64]);
    let first = endpoint.poll_datagram(now, 96).unwrap();
    let second = endpoint
        .poll_datagram(now + Duration::from_millis(20), 96)
        .unwrap();
    let third = endpoint
        .poll_datagram(now + Duration::from_millis(40), 96)
        .unwrap();
    assert_eq!(first.rotation_epoch, 0);
    assert_eq!(second.rotation_epoch, 0);
    assert!(third.rotation_epoch >= 1);
    assert_ne!(third.connection_id, first.connection_id);
}

#[test]
fn dplpmtud_probe_confirms_larger_payload() {
    let mut endpoint = TransportEndpoint::new(
        ConnectionId([7u8; 8]),
        [6u8; 32],
        TransportConfig {
            max_datagram_payload: 1320,
            ..TransportConfig::default()
        },
    );
    endpoint.debug_force_probe_due();
    endpoint.queue_keepalive();

    let now = Instant::now();
    let datagram = endpoint.poll_datagram(now, 1320).unwrap();
    assert!(
        datagram.encoded_len > 1100,
        "probe should exceed conservative starting payload"
    );
    assert!(datagram
        .frames
        .iter()
        .any(|frame| matches!(frame, TransportFrame::Padding(_))));

    let ack = AckFrame::normalized(
        vec![AckRange::new(
            datagram.packet_number,
            datagram.packet_number,
        )],
        1_000,
    );
    endpoint.on_datagram_received(
        now + Duration::from_millis(50),
        50,
        &[TransportFrame::Ack(ack)],
    );
    let snapshot = endpoint.snapshot();
    assert!(snapshot.path.confirmed_payload >= datagram.encoded_len);
    assert!(matches!(
        snapshot.path.mode,
        PathMode::Recovering | PathMode::Stable
    ));
}

#[test]
fn blackhole_detection_reduces_payload_budget() {
    let mut endpoint = TransportEndpoint::new(
        ConnectionId([8u8; 8]),
        [7u8; 32],
        TransportConfig {
            max_datagram_payload: 1320,
            ..TransportConfig::default()
        },
    );
    endpoint.debug_force_probe_due();
    let now = Instant::now();
    for i in 0..6 {
        endpoint.queue_message(TrafficClass::Interactive, vec![i as u8; 900]);
        let _ = endpoint.poll_datagram(now + Duration::from_millis(i * 20), 1320);
    }

    let before = endpoint.snapshot().path.payload_budget;
    let _ = endpoint.poll_datagram(now + Duration::from_millis(420), 1320);
    let after = endpoint.snapshot().path.payload_budget;
    assert!(
        after < before,
        "blackhole fallback should lower payload budget"
    );
    assert!(endpoint.snapshot().path.blackhole_suspected);
    assert_eq!(endpoint.snapshot().path.mode, PathMode::BlackholeRecovery);
}
