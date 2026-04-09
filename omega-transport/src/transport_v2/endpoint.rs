use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

use serde::Serialize;

use omega_core_wire::{
    AckFrame, ConnectionId, ControlFrame, ControlKind, DataFrame, FecFrame, PathFrame,
    TrafficClass, TransportFrame,
};

use super::ack::{AckTracker, CompletedMessage, ReassemblyBuffer};
use super::cc::{CongestionController, Pacer};
use super::path::{PathAckObservation, PathLossObservation, PathManager, PathSnapshot};
use super::queue::{
    data_frame_overhead, derive_connection_id, packet_is_lost, principal_class, QueuedMessage,
    SentPacket, SentStatus,
};

#[derive(Debug, Clone, Copy)]
pub struct TransportConfig {
    pub max_datagram_payload: usize,
    pub ack_delay: Duration,
    pub initial_rtt: Duration,
    pub min_rtt: Duration,
    pub initial_cwnd_packets: usize,
    pub min_cwnd_packets: usize,
    pub bulk_cwnd_share_num: usize,
    pub bulk_cwnd_share_den: usize,
    pub packet_threshold: u32,
    pub connection_id_rotation_interval_packets: u32,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            max_datagram_payload: 1100,
            ack_delay: Duration::from_millis(0),
            initial_rtt: Duration::from_millis(120),
            min_rtt: Duration::from_millis(20),
            initial_cwnd_packets: 10,
            min_cwnd_packets: 2,
            bulk_cwnd_share_num: 7,
            bulk_cwnd_share_den: 10,
            packet_threshold: 3,
            connection_id_rotation_interval_packets: 96,
        }
    }
}

#[derive(Debug, Clone)]
pub struct OutboundDatagram {
    pub packet_number: u32,
    pub frames: Vec<TransportFrame>,
    pub encoded_len: usize,
    pub ack_eliciting: bool,
    pub congestion_controlled: bool,
    pub principal_class: TrafficClass,
    pub connection_id: ConnectionId,
    pub rotation_epoch: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct TransportSnapshot {
    pub cwnd_bytes: usize,
    pub ssthresh_bytes: usize,
    pub bytes_in_flight: usize,
    pub pacing_rate_bps: u64,
    pub srtt_ms: u64,
    pub rttvar_ms: u64,
    pub min_rtt_ms: u64,
    pub loss_events: u64,
    pub spurious_loss_events: u64,
    pub pending_control: usize,
    pub pending_interactive: usize,
    pub pending_bulk: usize,
    pub active_connection_id: [u8; 8],
    pub peer_connection_id: [u8; 8],
    pub rotation_epoch: u32,
    pub path: PathSnapshot,
}

pub struct TransportEndpoint {
    config: TransportConfig,
    next_packet_number: u32,
    next_message_id: u32,
    control_queue: VecDeque<TransportFrame>,
    retransmit_queue: VecDeque<TransportFrame>,
    interactive_queue: VecDeque<QueuedMessage>,
    bulk_queue: VecDeque<QueuedMessage>,
    sent_packets: BTreeMap<u32, SentPacket>,
    reassembly: BTreeMap<u32, ReassemblyBuffer>,
    ack_tracker: AckTracker,
    cc: CongestionController,
    pacer: Pacer,
    path: PathManager,
    next_data_class: TrafficClass,
    active_connection_id: ConnectionId,
    peer_connection_id: ConnectionId,
    rotation_epoch: u32,
    transport_secret: [u8; 32],
}

impl TransportEndpoint {
    pub fn new(
        initial_connection_id: ConnectionId,
        transport_secret: [u8; 32],
        config: TransportConfig,
    ) -> Self {
        let cc = CongestionController::new(
            config.max_datagram_payload,
            config.initial_cwnd_packets,
            config.min_cwnd_packets,
            config.initial_rtt,
            config.min_rtt,
        );
        let path = PathManager::new(
            config.max_datagram_payload,
            config.initial_rtt,
            config.min_rtt,
        );
        Self {
            config,
            next_packet_number: 0,
            next_message_id: 0,
            control_queue: VecDeque::new(),
            retransmit_queue: VecDeque::new(),
            interactive_queue: VecDeque::new(),
            bulk_queue: VecDeque::new(),
            sent_packets: BTreeMap::new(),
            reassembly: BTreeMap::new(),
            ack_tracker: AckTracker::new(config.ack_delay),
            cc,
            pacer: Pacer::new(),
            path,
            next_data_class: TrafficClass::Interactive,
            active_connection_id: initial_connection_id,
            peer_connection_id: initial_connection_id,
            rotation_epoch: 0,
            transport_secret,
        }
    }

    pub fn queue_message(&mut self, class: TrafficClass, payload: Vec<u8>) -> u32 {
        let message_id = self.next_message_id;
        self.next_message_id = self.next_message_id.wrapping_add(1);
        self.enqueue_message(class, message_id, payload);
        message_id
    }

    pub fn queue_duplicate_message(
        &mut self,
        message_id: u32,
        class: TrafficClass,
        payload: Vec<u8>,
    ) {
        self.enqueue_message(class, message_id, payload);
    }

    pub fn discard_message(&mut self, message_id: u32) {
        self.reassembly.remove(&message_id);
    }

    fn enqueue_message(&mut self, class: TrafficClass, message_id: u32, payload: Vec<u8>) {
        let queued = QueuedMessage {
            class,
            message_id,
            payload,
            offset: 0,
        };
        match class {
            TrafficClass::Control => self
                .control_queue
                .push_back(TransportFrame::Data(queued.as_single_frame())),
            TrafficClass::Interactive => self.interactive_queue.push_back(queued),
            TrafficClass::Bulk => self.bulk_queue.push_back(queued),
        }
    }

    pub fn queue_control(&mut self, kind: ControlKind, data: Vec<u8>) {
        self.control_queue
            .push_back(TransportFrame::Control(ControlFrame { kind, data }));
    }

    pub fn queue_keepalive(&mut self) {
        self.queue_control(ControlKind::KeepAlive, Vec::new());
    }

    pub fn queue_fec_frame(&mut self, frame: FecFrame) {
        self.control_queue.push_back(TransportFrame::Fec(frame));
    }

    pub fn queue_close(&mut self) {
        self.queue_control(ControlKind::Close, Vec::new());
    }

    pub fn queue_path_feedback(&mut self, flags: u8) {
        self.control_queue.push_back(self.build_path_frame(flags));
    }

    pub fn note_peer_roam(&mut self, now: Instant) {
        self.path.note_peer_roam(now);
    }

    pub fn has_pending_work(&self) -> bool {
        !self.control_queue.is_empty()
            || !self.retransmit_queue.is_empty()
            || !self.interactive_queue.is_empty()
            || !self.bulk_queue.is_empty()
            || self.ack_tracker.has_pending_ack()
    }

    pub fn next_send_deadline(&self) -> Option<Instant> {
        if self.has_pending_work() {
            Some(self.pacer.next_send_time())
        } else {
            None
        }
    }

    pub fn poll_datagram(
        &mut self,
        now: Instant,
        payload_budget: usize,
    ) -> Option<OutboundDatagram> {
        self.poll_datagram_shaped(now, payload_budget, None)
    }

    pub fn poll_datagram_shaped(
        &mut self,
        now: Instant,
        payload_budget: usize,
        target_payload_floor: Option<usize>,
    ) -> Option<OutboundDatagram> {
        self.detect_losses(now);
        self.maybe_rotate_connection_id();

        let has_cc_work = !self.retransmit_queue.is_empty()
            || !self.control_queue.is_empty()
            || !self.interactive_queue.is_empty()
            || !self.bulk_queue.is_empty();
        if has_cc_work && !self.pacer.can_send(now) {
            return None;
        }

        let outer_limit = payload_budget.min(self.config.max_datagram_payload);
        let confirmed_budget = self.path.payload_budget(outer_limit);
        let probe_target = self.path.maybe_probe_target(now, outer_limit);
        let budget = probe_target.unwrap_or(confirmed_budget).min(outer_limit);
        if budget < 32 {
            return None;
        }

        let mut frames = Vec::new();
        let mut remaining = budget;

        if let Some(ack_frame) = self.ack_tracker.build_if_due(now) {
            let frame = TransportFrame::Ack(ack_frame);
            if frame.encoded_len() <= remaining {
                remaining -= frame.encoded_len();
                frames.push(frame);
            } else {
                self.ack_tracker.mark_immediate();
            }
        }

        while let Some(frame) = self.pop_priority_frame(remaining) {
            let frame_len = frame.encoded_len();
            if frame_len > remaining {
                break;
            }
            remaining -= frame_len;
            frames.push(frame);
        }

        while remaining > data_frame_overhead() + 1 {
            let control_only = frames.iter().all(|frame| !frame.congestion_controlled());
            if !control_only && self.cc.bytes_in_flight() >= self.cc.send_limit() {
                break;
            }

            let Some(frame) = self.pop_next_data_frame(remaining) else {
                break;
            };
            let frame_len = frame.encoded_len();
            if frame_len > remaining {
                break;
            }
            remaining -= frame_len;
            frames.push(frame);
        }

        if frames.is_empty() {
            return None;
        }

        let mut ack_eliciting = frames.iter().any(TransportFrame::is_ack_eliciting);
        if probe_target.is_some() && !ack_eliciting {
            let path_frame = self.build_path_frame(0x02);
            if path_frame.encoded_len() <= remaining {
                frames.push(path_frame);
                ack_eliciting = true;
            }
        }

        if probe_target.is_some() {
            let current_len: usize = frames.iter().map(TransportFrame::encoded_len).sum();
            let delta = budget.saturating_sub(current_len);
            if ack_eliciting && delta >= 3 {
                frames.push(TransportFrame::Padding(delta - 3));
            }
        } else if let Some(target_floor) = target_payload_floor {
            let current_len: usize = frames.iter().map(TransportFrame::encoded_len).sum();
            let desired_floor = target_floor.min(budget);
            let delta = desired_floor.saturating_sub(current_len);
            if delta >= 3 {
                frames.push(TransportFrame::Padding(delta - 3));
            }
        }

        let encoded_len: usize = frames.iter().map(TransportFrame::encoded_len).sum();
        let probe_target_sent =
            if probe_target.is_some() && ack_eliciting && encoded_len > confirmed_budget {
                self.path.on_probe_sent(now, encoded_len);
                Some(encoded_len)
            } else {
                None
            };

        let packet_number = self.next_packet_number;
        self.next_packet_number = self.next_packet_number.wrapping_add(1);
        let congestion_controlled = frames.iter().any(TransportFrame::congestion_controlled);
        let principal_class = principal_class(&frames);

        self.sent_packets.insert(
            packet_number,
            SentPacket {
                sent_at: now,
                bytes: encoded_len,
                congestion_controlled,
                principal_class,
                frames: frames.clone(),
                status: SentStatus::InFlight,
                path_probe_target: probe_target_sent,
            },
        );
        self.cc
            .on_packet_sent(principal_class, encoded_len, congestion_controlled);
        self.pacer.on_packet_sent(
            now,
            encoded_len,
            self.path.effective_pacing_rate(self.cc.pacing_rate_bps()),
        );

        Some(OutboundDatagram {
            packet_number,
            frames,
            encoded_len,
            ack_eliciting,
            congestion_controlled,
            principal_class,
            connection_id: self.active_connection_id,
            rotation_epoch: self.rotation_epoch,
        })
    }

    pub fn abort_sent(&mut self, packet_number: u32) {
        if let Some(sent) = self.sent_packets.remove(&packet_number) {
            if sent.status == SentStatus::InFlight {
                self.cc
                    .on_abort(sent.principal_class, sent.bytes, sent.congestion_controlled);
                self.requeue_frames_front(sent.frames);
            }
        }
    }

    pub fn on_datagram_received(
        &mut self,
        now: Instant,
        packet_number: u32,
        frames: &[TransportFrame],
    ) -> Vec<CompletedMessage> {
        let ack_eliciting = frames.iter().any(TransportFrame::is_ack_eliciting);
        self.ack_tracker.observe(packet_number, ack_eliciting, now);

        let mut messages = Vec::new();
        for frame in frames {
            match frame {
                TransportFrame::Data(data) => {
                    if let Some(message) = self.process_data_frame(now, data.clone()) {
                        messages.push(message);
                    }
                }
                TransportFrame::Ack(ack) => self.process_ack_frame(now, ack),
                TransportFrame::Control(control) => {
                    if matches!(control.kind, ControlKind::KeepAlive) {
                        continue;
                    }
                }
                TransportFrame::Path(path) => {
                    self.peer_connection_id = path.next_connection_id;
                    if (path.flags & 0x04) != 0 {
                        self.path.note_peer_roam(now);
                    }
                }
                TransportFrame::Fec(_) | TransportFrame::Padding(_) => {}
            }
        }

        self.prune_reassembly(now);
        self.detect_losses(now);
        messages
    }

    pub fn snapshot(&self) -> TransportSnapshot {
        TransportSnapshot {
            cwnd_bytes: self.cc.cwnd_bytes,
            ssthresh_bytes: self.cc.ssthresh_bytes,
            bytes_in_flight: self.cc.bytes_in_flight,
            pacing_rate_bps: self.path.effective_pacing_rate(self.cc.pacing_rate_bps),
            srtt_ms: self.cc.smoothed_rtt.as_millis() as u64,
            rttvar_ms: self.cc.rttvar.as_millis() as u64,
            min_rtt_ms: self.cc.min_rtt.as_millis() as u64,
            loss_events: self.cc.loss_events,
            spurious_loss_events: self.cc.spurious_loss_events,
            pending_control: self.control_queue.len() + self.retransmit_queue.len(),
            pending_interactive: self.interactive_queue.len(),
            pending_bulk: self.bulk_queue.len(),
            active_connection_id: self.active_connection_id.0,
            peer_connection_id: self.peer_connection_id.0,
            rotation_epoch: self.rotation_epoch,
            path: self
                .path
                .snapshot(self.config.max_datagram_payload, Instant::now()),
        }
    }

    #[cfg(test)]
    pub(crate) fn debug_force_probe_due(&mut self) {
        self.path.debug_force_probe_due();
    }

    fn process_data_frame(&mut self, now: Instant, frame: DataFrame) -> Option<CompletedMessage> {
        let total_len = frame.message_len as usize;
        let message_id = frame.message_id;
        let completed = {
            let entry = self
                .reassembly
                .entry(message_id)
                .or_insert_with(|| ReassemblyBuffer::new(message_id, frame.class, total_len, now));
            entry.insert(frame, now)
        };
        if completed.is_some() {
            self.reassembly.remove(&message_id);
        }
        completed
    }

    fn prune_reassembly(&mut self, now: Instant) {
        self.reassembly
            .retain(|_, buffer| now.duration_since(buffer.last_update) <= Duration::from_secs(15));
    }

    fn build_path_frame(&self, flags: u8) -> TransportFrame {
        TransportFrame::Path(PathFrame {
            flags,
            observed_rtt_micros: self.cc.smoothed_rtt.as_micros().min(u32::MAX as u128) as u32,
            delivery_rate_kbps: (self.path.effective_pacing_rate(self.cc.pacing_rate_bps()) / 1_000)
                as u32,
            next_connection_id: self.active_connection_id,
            rotation_epoch: self.rotation_epoch,
        })
    }

    fn pop_priority_frame(&mut self, remaining: usize) -> Option<TransportFrame> {
        if let Some(frame) = self.retransmit_queue.front() {
            if frame.encoded_len() <= remaining {
                return self.retransmit_queue.pop_front();
            }
        }
        if let Some(frame) = self.control_queue.front() {
            if frame.encoded_len() <= remaining {
                return self.control_queue.pop_front();
            }
        }
        None
    }

    fn pop_next_data_frame(&mut self, remaining: usize) -> Option<TransportFrame> {
        let max_bulk_in_flight = self
            .cc
            .send_limit()
            .saturating_mul(self.config.bulk_cwnd_share_num)
            / self.config.bulk_cwnd_share_den.max(1);
        let bulk_allowed = self.cc.bulk_in_flight() < max_bulk_in_flight;
        let prefer_interactive = match self.next_data_class {
            TrafficClass::Interactive => true,
            TrafficClass::Bulk => !self.interactive_queue.is_empty() && !bulk_allowed,
            TrafficClass::Control => true,
        };
        let first = if prefer_interactive {
            TrafficClass::Interactive
        } else {
            TrafficClass::Bulk
        };
        let second = if first == TrafficClass::Interactive {
            TrafficClass::Bulk
        } else {
            TrafficClass::Interactive
        };

        if let Some(frame) = self.pop_data_frame_for_class(first, remaining, bulk_allowed) {
            self.next_data_class = second;
            return Some(frame);
        }
        if let Some(frame) = self.pop_data_frame_for_class(second, remaining, bulk_allowed) {
            self.next_data_class = first;
            return Some(frame);
        }
        None
    }

    fn pop_data_frame_for_class(
        &mut self,
        class: TrafficClass,
        remaining: usize,
        bulk_allowed: bool,
    ) -> Option<TransportFrame> {
        if class == TrafficClass::Bulk && !bulk_allowed {
            return None;
        }
        let queue = match class {
            TrafficClass::Interactive => &mut self.interactive_queue,
            TrafficClass::Bulk => &mut self.bulk_queue,
            TrafficClass::Control => return None,
        };
        let queued = queue.front_mut()?;
        if remaining <= data_frame_overhead() {
            return None;
        }
        let frame = queued.take_fragment(remaining - data_frame_overhead())?;
        if queued.is_complete() {
            queue.pop_front();
        }
        Some(TransportFrame::Data(frame))
    }

    fn process_ack_frame(&mut self, now: Instant, ack: &AckFrame) {
        let Some(largest_acked) = ack.largest_acked() else {
            return;
        };

        let mut acked_entries = Vec::new();
        let mut lost_entries = Vec::new();
        let mut reordered_packets = 0u32;
        let mut spurious_reorders = 0u32;

        for (packet_number, sent) in self.sent_packets.iter_mut() {
            if sent.status == SentStatus::Acked {
                continue;
            }
            if ack.acks_packet(*packet_number) {
                if sent.status == SentStatus::Lost {
                    self.cc.spurious_loss_events = self.cc.spurious_loss_events.saturating_add(1);
                    spurious_reorders = spurious_reorders.saturating_add(1);
                }
                if *packet_number < largest_acked {
                    reordered_packets = reordered_packets.saturating_add(1);
                }
                sent.status = SentStatus::Acked;
                acked_entries.push((
                    sent.principal_class,
                    sent.bytes,
                    sent.sent_at,
                    sent.congestion_controlled,
                    sent.path_probe_target,
                ));
            } else if sent.status == SentStatus::InFlight
                && packet_is_lost(
                    *packet_number,
                    largest_acked,
                    sent.sent_at,
                    now,
                    self.cc.loss_delay(),
                    self.config.packet_threshold,
                )
            {
                sent.status = SentStatus::Lost;
                lost_entries.push((
                    sent.principal_class,
                    sent.bytes,
                    sent.congestion_controlled,
                    sent.frames.clone(),
                    sent.path_probe_target,
                ));
            }
        }

        let latest_rtt = acked_entries.last().map(|(_, _, sent_at, _, _)| {
            let ack_delay = Duration::from_micros(ack.ack_delay_micros as u64);
            now.saturating_duration_since(*sent_at)
                .saturating_sub(ack_delay)
        });
        if let Some(sample) = latest_rtt {
            self.cc.on_rtt_sample(sample);
        }

        let acked_bytes: usize = acked_entries.iter().map(|(_, bytes, _, _, _)| *bytes).sum();
        let acked_packets = acked_entries.len() as u32;
        let probe_success_payload = acked_entries
            .iter()
            .filter_map(|(_, _, _, _, probe)| *probe)
            .max();
        for (class, bytes, _, congestion_controlled, _) in acked_entries {
            self.cc.on_packet_acked(class, bytes, congestion_controlled);
        }

        self.path.on_ack_batch(
            now,
            PathAckObservation {
                acked_bytes,
                acked_packets,
                reordered_packets,
                spurious_reorders,
                latest_rtt,
                probe_success_payload,
            },
            self.cc.smoothed_rtt,
            self.cc.min_rtt,
        );

        if !lost_entries.is_empty() {
            let lost_bytes: usize = lost_entries.iter().map(|(_, bytes, _, _, _)| *bytes).sum();
            let lost_packets = lost_entries.len() as u32;
            let probe_failed_payload = lost_entries
                .iter()
                .filter_map(|(_, _, _, _, probe)| *probe)
                .max();
            let rtt_inflated = self.cc.smoothed_rtt > self.cc.min_rtt.mul_f32(1.20);
            let random_loss = lost_entries.len() == 1 && !rtt_inflated && acked_bytes >= lost_bytes;
            self.cc.on_loss(lost_bytes, random_loss);
            self.path.on_loss_batch(
                now,
                PathLossObservation {
                    acked_bytes,
                    lost_bytes,
                    acked_packets,
                    lost_packets,
                    probe_failed_payload,
                },
                self.cc.smoothed_rtt,
                self.cc.min_rtt,
            );
            for (_, _, _, frames, _) in lost_entries {
                self.requeue_frames_front(frames);
            }
        }

        self.sent_packets
            .retain(|_, sent| !matches!(sent.status, SentStatus::Acked));
    }

    fn requeue_frames_front(&mut self, frames: Vec<TransportFrame>) {
        for frame in frames.into_iter().rev() {
            match frame {
                TransportFrame::Ack(_) | TransportFrame::Padding(_) => {}
                other => self.retransmit_queue.push_front(other),
            }
        }
    }

    fn detect_losses(&mut self, now: Instant) {
        let Some(largest_sent) = self.sent_packets.keys().next_back().copied() else {
            return;
        };

        let mut lost_entries = Vec::new();
        for (packet_number, sent) in self.sent_packets.iter_mut() {
            if sent.status != SentStatus::InFlight {
                continue;
            }
            if packet_is_lost(
                *packet_number,
                largest_sent,
                sent.sent_at,
                now,
                self.cc.loss_delay(),
                self.config.packet_threshold,
            ) {
                sent.status = SentStatus::Lost;
                lost_entries.push((
                    sent.principal_class,
                    sent.bytes,
                    sent.congestion_controlled,
                    sent.frames.clone(),
                    sent.path_probe_target,
                ));
            }
        }

        if !lost_entries.is_empty() {
            let lost_bytes: usize = lost_entries.iter().map(|(_, bytes, _, _, _)| *bytes).sum();
            let lost_packets = lost_entries.len() as u32;
            let probe_failed_payload = lost_entries
                .iter()
                .filter_map(|(_, _, _, _, probe)| *probe)
                .max();
            let rtt_inflated = self.cc.smoothed_rtt > self.cc.min_rtt.mul_f32(1.20);
            let random_loss = lost_entries.len() == 1 && !rtt_inflated;
            self.cc.on_loss(lost_bytes, random_loss);
            self.path.on_loss_batch(
                now,
                PathLossObservation {
                    acked_bytes: 0,
                    lost_bytes,
                    acked_packets: 0,
                    lost_packets,
                    probe_failed_payload,
                },
                self.cc.smoothed_rtt,
                self.cc.min_rtt,
            );
            for (_, _, _, frames, _) in lost_entries {
                self.requeue_frames_front(frames);
            }
        }
    }

    fn maybe_rotate_connection_id(&mut self) {
        let interval = self.config.connection_id_rotation_interval_packets;
        if interval == 0 {
            return;
        }
        let next_epoch = self.next_packet_number / interval;
        if next_epoch == 0 || next_epoch <= self.rotation_epoch {
            return;
        }
        self.rotation_epoch = next_epoch;
        self.active_connection_id = derive_connection_id(&self.transport_secret, next_epoch);
        self.control_queue.push_back(self.build_path_frame(0x01));
    }
}
