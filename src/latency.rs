use std::{
    any::TypeId,
    cell::RefCell,
    collections::HashMap,
    time::{Duration, Instant},
};

#[derive(Debug, Clone, Default)]
pub struct Latency(Vec<(Instant, TypeId, u32)>);
thread_local! {
    static LATENCY: RefCell<Latency> = RefCell::new(Latency(vec![]));
}

pub fn push_latency<T: 'static>(i: u32) {
    LATENCY.with(|latency| {
        latency
            .borrow_mut()
            .0
            .push((Instant::now(), TypeId::of::<T>(), i))
    });
}

pub fn merge_latency_with(aggregated: &mut Latency) {
    LATENCY.with(|latency| {
        aggregated.0.extend(&latency.borrow().0);
    });
    aggregated.0.sort_unstable();
}

impl Latency {
    pub fn intervals<B: 'static, E: 'static>(&self) -> Vec<Duration> {
        let mut instances = HashMap::new();
        let (begin_tag, end_tag) = (TypeId::of::<B>(), TypeId::of::<E>());
        let mut intervals = vec![];
        for &(instant, tag, i) in &self.0 {
            if tag == begin_tag {
                instances.insert(i, instant);
            }
            if tag == end_tag {
                intervals.push(instant - instances.remove(&i).unwrap());
            }
        }
        intervals
    }
}
