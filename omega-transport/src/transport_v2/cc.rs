use std::time::{Duration, Instant};

use omega_core_wire::TrafficClass;

#[derive(Debug)]
pub(crate) struct CongestionController {
    max_datagram_size: usize,
    pub cwnd_bytes: usize,
    pub ssthresh_bytes: usize,
    pub bytes_in_flight: usize,
    interactive_in_flight: usize,
    bulk_in_flight: usize,
    pub smoothed_rtt: Duration,
    pub rttvar: Duration,
    pub min_rtt: Duration,
    latest_rtt: Duration,
    pub pacing_rate_bps: u64,
    pub loss_events: u64,
    pub spurious_loss_events: u64,
}

impl CongestionController {
    pub(crate) fn new(
        max_datagram_size: usize,
        initial_cwnd_packets: usize,
        min_cwnd_packets: usize,
        initial_rtt: Duration,
        min_rtt: Duration,
    ) -> Self {
        let min_cwnd = max_datagram_size.saturating_mul(min_cwnd_packets.max(2));
        let initial_cwnd = max_datagram_size.saturating_mul(initial_cwnd_packets.max(4));
        let cwnd_bytes = initial_cwnd.max(min_cwnd);
        let ssthresh_bytes = usize::MAX / 4;
        let pacing_rate_bps = ((cwnd_bytes as u128)
            .saturating_mul(8)
            .saturating_mul(1_000_000)
            / initial_rtt.as_micros().max(1)) as u64;
        Self {
            max_datagram_size,
            cwnd_bytes,
            ssthresh_bytes,
            bytes_in_flight: 0,
            interactive_in_flight: 0,
            bulk_in_flight: 0,
            smoothed_rtt: initial_rtt,
            rttvar: initial_rtt / 2,
            min_rtt,
            latest_rtt: initial_rtt,
            pacing_rate_bps,
            loss_events: 0,
            spurious_loss_events: 0,
        }
    }

    pub(crate) fn on_rtt_sample(&mut self, sample: Duration) {
        if sample.is_zero() {
            return;
        }
        self.latest_rtt = sample;
        self.min_rtt = self.min_rtt.min(sample);
        let delta = (self.smoothed_rtt.as_micros() as i128 - sample.as_micros() as i128)
            .unsigned_abs() as u128;
        let rttvar_us = (self.rttvar.as_micros() * 3 + delta) / 4;
        let smoothed_us = (self.smoothed_rtt.as_micros() * 7 + sample.as_micros()) / 8;
        self.rttvar = Duration::from_micros(rttvar_us.min(u64::MAX as u128) as u64);
        self.smoothed_rtt = Duration::from_micros(smoothed_us.min(u64::MAX as u128) as u64);
        self.recompute_pacing_rate();
    }

    pub(crate) fn on_packet_sent(
        &mut self,
        class: TrafficClass,
        bytes: usize,
        congestion_controlled: bool,
    ) {
        if !congestion_controlled {
            return;
        }
        self.bytes_in_flight = self.bytes_in_flight.saturating_add(bytes);
        match class {
            TrafficClass::Bulk => self.bulk_in_flight = self.bulk_in_flight.saturating_add(bytes),
            TrafficClass::Interactive | TrafficClass::Control => {
                self.interactive_in_flight = self.interactive_in_flight.saturating_add(bytes)
            }
        }
    }

    pub(crate) fn on_packet_acked(
        &mut self,
        class: TrafficClass,
        bytes: usize,
        congestion_controlled: bool,
    ) {
        if congestion_controlled {
            self.bytes_in_flight = self.bytes_in_flight.saturating_sub(bytes);
            match class {
                TrafficClass::Bulk => {
                    self.bulk_in_flight = self.bulk_in_flight.saturating_sub(bytes)
                }
                TrafficClass::Interactive | TrafficClass::Control => {
                    self.interactive_in_flight = self.interactive_in_flight.saturating_sub(bytes)
                }
            }
        }

        if self.cwnd_bytes < self.ssthresh_bytes {
            self.cwnd_bytes = self.cwnd_bytes.saturating_add(bytes);
        } else {
            let growth =
                self.max_datagram_size.saturating_mul(bytes.max(1)) / self.cwnd_bytes.max(1);
            self.cwnd_bytes = self.cwnd_bytes.saturating_add(growth.max(1));
        }
        self.recompute_pacing_rate();
    }

    pub(crate) fn on_loss(&mut self, lost_bytes: usize, random_loss: bool) {
        if lost_bytes == 0 {
            return;
        }
        self.loss_events = self.loss_events.saturating_add(1);
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(lost_bytes);
        let min_cwnd = self.max_datagram_size.saturating_mul(64);
        if random_loss {
            // Random/isolated loss — gentle 5% reduction (was 10%).
            // VPN packet loss is usually WiFi/mobile, not congestion.
            self.cwnd_bytes = self
                .cwnd_bytes
                .saturating_mul(19)
                .checked_div(20)
                .unwrap_or(self.cwnd_bytes)
                .max(min_cwnd);
        } else {
            // Deterministic loss — 25% reduction (was 50%).
            // Halving is too aggressive for a VPN tunnel where inner TCP
            // already handles its own congestion control.
            self.ssthresh_bytes = (self.cwnd_bytes * 3 / 4).max(min_cwnd);
            self.cwnd_bytes = self.ssthresh_bytes;
        }
        self.recompute_pacing_rate();
    }

    pub(crate) fn on_abort(
        &mut self,
        class: TrafficClass,
        bytes: usize,
        congestion_controlled: bool,
    ) {
        if !congestion_controlled {
            return;
        }
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(bytes);
        match class {
            TrafficClass::Bulk => self.bulk_in_flight = self.bulk_in_flight.saturating_sub(bytes),
            TrafficClass::Interactive | TrafficClass::Control => {
                self.interactive_in_flight = self.interactive_in_flight.saturating_sub(bytes)
            }
        }
    }

    pub(crate) fn loss_delay(&self) -> Duration {
        let base = self.latest_rtt.max(self.smoothed_rtt);
        let micros = (base.as_micros() * 9) / 8;
        Duration::from_micros(micros.min(u64::MAX as u128) as u64)
    }

    pub(crate) fn send_limit(&self) -> usize {
        self.cwnd_bytes
            .max(self.max_datagram_size.saturating_mul(64))
    }

    pub(crate) fn bytes_in_flight(&self) -> usize {
        self.bytes_in_flight
    }

    pub(crate) fn bulk_in_flight(&self) -> usize {
        self.bulk_in_flight
    }

    pub(crate) fn pacing_rate_bps(&self) -> u64 {
        self.pacing_rate_bps.max(10_000_000)
    }

    fn recompute_pacing_rate(&mut self) {
        let (gain_num, gain_den) = if self.cwnd_bytes < self.ssthresh_bytes {
            (5u128, 4u128)
        } else {
            (4u128, 3u128)
        };
        let base = (self.cwnd_bytes as u128)
            .saturating_mul(8)
            .saturating_mul(1_000_000)
            / self.smoothed_rtt.as_micros().max(1);
        self.pacing_rate_bps = (base.saturating_mul(gain_num) / gain_den)
            .max(1_000)
            .min(u64::MAX as u128) as u64;
    }
}

#[derive(Debug)]
pub(crate) struct Pacer {
    next_send_time: Instant,
}

impl Pacer {
    pub(crate) fn new() -> Self {
        Self {
            next_send_time: Instant::now(),
        }
    }

    pub(crate) fn can_send(&self, now: Instant) -> bool {
        now >= self.next_send_time
    }

    pub(crate) fn on_packet_sent(&mut self, now: Instant, bytes: usize, pacing_rate_bps: u64) {
        let interval_micros = ((bytes as u128).saturating_mul(8).saturating_mul(1_000_000)
            / pacing_rate_bps.max(1) as u128)
            .max(50);
        self.next_send_time =
            now + Duration::from_micros(interval_micros.min(u64::MAX as u128) as u64);
    }

    pub(crate) fn next_send_time(&self) -> Instant {
        self.next_send_time
    }
}
