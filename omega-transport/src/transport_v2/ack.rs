use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use omega_core_wire::{AckFrame, AckRange, DataFrame, TrafficClass, MAX_ACK_RANGES};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletedMessage {
    pub message_id: u32,
    pub class: TrafficClass,
    pub payload: Vec<u8>,
}

#[derive(Debug)]
pub(crate) struct ReassemblyBuffer {
    message_id: u32,
    class: TrafficClass,
    total_len: usize,
    received_len: usize,
    chunks: BTreeMap<usize, Vec<u8>>,
    pub last_update: Instant,
}

impl ReassemblyBuffer {
    pub(crate) fn new(
        message_id: u32,
        class: TrafficClass,
        total_len: usize,
        now: Instant,
    ) -> Self {
        Self {
            message_id,
            class,
            total_len,
            received_len: 0,
            chunks: BTreeMap::new(),
            last_update: now,
        }
    }

    pub(crate) fn insert(&mut self, frame: DataFrame, now: Instant) -> Option<CompletedMessage> {
        self.last_update = now;
        let offset = frame.fragment_offset as usize;
        if offset > self.total_len || offset.saturating_add(frame.payload.len()) > self.total_len {
            return None;
        }
        if !self.chunks.contains_key(&offset) {
            self.received_len = self.received_len.saturating_add(frame.payload.len());
            self.chunks.insert(offset, frame.payload);
        }
        if self.received_len < self.total_len {
            return None;
        }

        let mut cursor = 0usize;
        let mut out = Vec::with_capacity(self.total_len);
        for (offset, chunk) in &self.chunks {
            if *offset != cursor {
                return None;
            }
            out.extend_from_slice(chunk);
            cursor += chunk.len();
        }
        if cursor != self.total_len {
            return None;
        }

        Some(CompletedMessage {
            message_id: self.message_id,
            class: self.class,
            payload: out,
        })
    }
}

#[derive(Debug)]
pub(crate) struct AckTracker {
    ack_delay: Duration,
    received: BTreeSet<u32>,
    largest_seen: Option<u32>,
    largest_seen_at: Option<Instant>,
    pending_due_at: Option<Instant>,
    force_immediate: bool,
}

impl AckTracker {
    pub(crate) fn new(ack_delay: Duration) -> Self {
        Self {
            ack_delay,
            received: BTreeSet::new(),
            largest_seen: None,
            largest_seen_at: None,
            pending_due_at: None,
            force_immediate: false,
        }
    }

    pub(crate) fn observe(&mut self, packet_number: u32, ack_eliciting: bool, now: Instant) {
        let previous_largest = self.largest_seen;
        self.received.insert(packet_number);
        if self.received.len() > 2048 {
            if let Some(largest) = self.largest_seen {
                let floor = largest.saturating_sub(1024);
                self.received.retain(|value| *value >= floor);
            }
        }
        if previous_largest.map_or(true, |largest| packet_number > largest) {
            self.largest_seen = Some(packet_number);
            self.largest_seen_at = Some(now);
        } else if previous_largest.is_some() {
            self.force_immediate = true;
        }

        if ack_eliciting {
            self.pending_due_at = Some(now + self.ack_delay);
        }
    }

    pub(crate) fn has_pending_ack(&self) -> bool {
        self.pending_due_at.is_some() || self.force_immediate
    }

    pub(crate) fn build_if_due(&mut self, now: Instant) -> Option<AckFrame> {
        let due = self.force_immediate
            || self
                .pending_due_at
                .map_or(false, |deadline| now >= deadline);
        if !due {
            return None;
        }
        let ack = self.build_ack_frame(now)?;
        self.pending_due_at = None;
        self.force_immediate = false;
        Some(ack)
    }

    pub(crate) fn build_ack_frame(&self, now: Instant) -> Option<AckFrame> {
        let largest_seen_at = self.largest_seen_at?;
        let mut ranges = Vec::new();
        let mut current_end = None::<u32>;
        let mut current_start = 0u32;

        for packet_number in self.received.iter().rev() {
            match current_end {
                None => {
                    current_end = Some(*packet_number);
                    current_start = *packet_number;
                }
                Some(end) if packet_number.saturating_add(1) == current_start => {
                    current_start = *packet_number;
                    current_end = Some(end);
                }
                Some(end) => {
                    ranges.push(AckRange::new(current_start, end));
                    if ranges.len() >= MAX_ACK_RANGES {
                        break;
                    }
                    current_start = *packet_number;
                    current_end = Some(*packet_number);
                }
            }
        }

        if let Some(end) = current_end {
            if ranges.len() < MAX_ACK_RANGES {
                ranges.push(AckRange::new(current_start, end));
            }
        }

        Some(AckFrame::normalized(
            ranges,
            now.saturating_duration_since(largest_seen_at)
                .as_micros()
                .min(u32::MAX as u128) as u32,
        ))
    }

    pub(crate) fn mark_immediate(&mut self) {
        self.force_immediate = true;
    }
}
