//! Behavioral contract for cooperative restartable-ECP polling.

use core::future::{poll_fn, Future};
use core::pin::pin;
use core::task::{Context, Poll, Waker};
use std::cell::Cell;
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::Wake;

const MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS: i32 = -0x7000;

async fn call_restartable(mut operation: impl FnMut() -> i32) -> i32 {
    poll_fn(|context| {
        let result = operation();
        if result == MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS {
            context.waker().wake_by_ref();
            Poll::Pending
        } else {
            Poll::Ready(result)
        }
    })
    .await
}

struct CountingWake(AtomicUsize);

impl Wake for CountingWake {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

#[test]
fn crypto_in_progress_retries_the_same_operation_on_the_next_poll() {
    let calls = Rc::new(Cell::new(0));
    let calls_for_operation = calls.clone();
    let mut future = pin!(call_restartable(move || {
        calls_for_operation.set(calls_for_operation.get() + 1);
        if calls_for_operation.get() == 1 {
            MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS
        } else {
            7
        }
    },));
    let wake_count = Arc::new(CountingWake(AtomicUsize::new(0)));
    let waker = Waker::from(wake_count.clone());
    let mut context = Context::from_waker(&waker);

    assert_eq!(Future::poll(future.as_mut(), &mut context), Poll::Pending);
    assert_eq!(calls.get(), 1);
    assert_eq!(wake_count.0.load(Ordering::Relaxed), 1);
    assert_eq!(Future::poll(future.as_mut(), &mut context), Poll::Ready(7));
    assert_eq!(calls.get(), 2);
}

#[test]
fn other_results_complete_without_a_cooperative_retry() {
    for result in [0, -0x6900, -1] {
        let mut future = pin!(call_restartable(|| result));
        let wake_count = Arc::new(CountingWake(AtomicUsize::new(0)));
        let waker = Waker::from(wake_count.clone());
        let mut context = Context::from_waker(&waker);

        assert_eq!(
            Future::poll(future.as_mut(), &mut context),
            Poll::Ready(result)
        );
        assert_eq!(wake_count.0.load(Ordering::Relaxed), 0);
    }
}
