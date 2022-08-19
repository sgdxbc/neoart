use std::{
    cell::RefCell,
    collections::HashMap,
    time::{Duration, Instant},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Point {
    RequestBegin(u32),
    RequestEnd(u32),
    // TransportBegin,
    // TransportEnd,
    // ReceiverBegin,
    // ReceiverEnd,
    // CryptoSubmitBegin,
    // CryptoSubmitEnd,
}

#[derive(Debug, Clone, Default)]
pub struct Latency(Vec<(Instant, Point)>);
thread_local! {
    static LATENCY: RefCell<Latency> = RefCell::new(Latency(vec![]));
}

pub fn push_latency(point: Point) {
    LATENCY.with(|latency| latency.borrow_mut().0.push((Instant::now(), point)));
}

pub fn merge_latency_into(aggregated: &mut Latency) {
    LATENCY.with(|latency| {
        aggregated.0.extend(&latency.borrow().0);
    });
    // aggregated.0.sort_unstable();
}

impl Latency {
    pub fn sort(&mut self) {
        self.0.sort_unstable();
    }

    pub fn intervals(&self, begin: Point, end: Point) -> Vec<Duration> {
        let mut begin_instant = None;
        let mut intervals = Vec::new();
        for &(instant, point) in &self.0 {
            if point == begin {
                begin_instant = Some(instant);
            }
            if point == end {
                intervals.push(instant - begin_instant.take().unwrap());
            }
        }
        intervals
    }

    pub fn trim(&self, start: u64, duration: u64) -> Self {
        if self.0.is_empty() {
            return Self(Vec::new());
        }
        let start = self.0[0].0 + Duration::from_millis(start);
        let duration = Duration::from_millis(duration);
        Self(
            self.0
                .iter()
                .filter(|&&(instant, _)| instant >= start && instant < start + duration)
                .copied()
                .collect(),
        )
    }

    pub fn interval_table(&self) -> HashMap<(Point, Point), Vec<Duration>> {
        let mut table: HashMap<_, Vec<_>> = HashMap::new();
        for (&(start_instant, start_point), &(end_instant, end_point)) in
            self.0.iter().zip(self.0.iter().skip(1))
        {
            if end_instant - start_instant > Duration::from_secs(1) {
                continue;
            }
            table
                .entry((start_point, end_point))
                .or_default()
                .push(end_instant - start_instant);
        }
        table
    }
}
