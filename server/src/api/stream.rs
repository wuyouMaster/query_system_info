use axum::extract::{Path, Query, State};
use axum::response::sse::{Event, Sse};
use futures::stream::{self, Stream};
use serde::Deserialize;
use std::convert::Infallible;
use std::pin::Pin;
use std::time::Duration;

use super::super::state::AppState;

type BoxSseStream = Pin<Box<dyn Stream<Item = Result<Event, Infallible>> + Send>>;

#[derive(Deserialize)]
pub struct StreamParams {
    pub interval: Option<u64>,
}

#[derive(Deserialize)]
pub struct ProcessStreamParams {
    pub stream_type: Option<String>,
}

pub async fn cpu_usage(
    State(state): State<AppState>,
    Query(params): Query<StreamParams>,
) -> Sse<BoxSseStream> {
    let interval_ms = params.interval.unwrap_or(1000);
    let interval = Duration::from_millis(interval_ms);
    let cache = state.cpu_usage_cache;

    let sse_stream = stream::unfold((), move |()| {
        let c = cache.clone();
        async move {
            let event = match c.samples.latest() {
                Some(usage) => {
                    let data = serde_json::to_string(&usage).unwrap_or_default();
                    Ok(Event::default().event("cpu_usage").data(data))
                }
                None => Ok(
                    Event::default()
                        .event("cpu_usage")
                        .data("[]"),
                ),
            };

            tokio::time::sleep(interval).await;
            Some((event, ()))
        }
    });

    Sse::new(Box::pin(sse_stream))
}

pub async fn process_tracker(
    Path(pid): Path<u32>,
    Query(params): Query<ProcessStreamParams>,
    State(state): State<AppState>,
) -> Sse<BoxSseStream> {
    let stream_type = params.stream_type.unwrap_or_else(|| "all".to_string());

    // Use ProcessTraceCache for per-PID data (memory/io/cpu samples)
    let trace_entry = state.trace_cache.get_or_subscribe(pid).await;
    let mut trace_rx = trace_entry.event_tx.subscribe();

    // Use TrackerManager for child/socket real-time events
    let sse_stream: BoxSseStream = match stream_type.as_str() {
        "children" => {
            let mut rx = state.get_or_create_child_channel(pid).await;
            Box::pin(async_stream::stream! {
                loop {
                    tokio::select! {
                        result = rx.recv() => {
                            match result {
                                Ok(event) => {
                                    let data = serde_json::to_string(&event).unwrap_or_default();
                                    yield Ok(Event::default().event("child_process").data(data));
                                }
                                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                                    yield Ok(Event::default()
                                        .event("warning")
                                        .data(format!("Skipped {} events", n)));
                                }
                                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                                    yield Ok(Event::default().event("end").data("channel closed"));
                                    break;
                                }
                            }
                        }
                        result = trace_rx.recv() => {
                            if let Ok(trace_event) = result {
                                let data = serde_json::to_string(&trace_event).unwrap_or_default();
                                yield Ok(Event::default().event("trace_sample").data(data));
                            }
                        }
                    }
                }
            })
        }
        "sockets" => {
            let mut rx = state.get_or_create_socket_channel(pid).await;
            Box::pin(async_stream::stream! {
                loop {
                    tokio::select! {
                        result = rx.recv() => {
                            match result {
                                Ok(event) => {
                                    let data = serde_json::to_string(&event).unwrap_or_default();
                                    yield Ok(Event::default().event("socket_connection").data(data));
                                }
                                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                                    yield Ok(Event::default()
                                        .event("warning")
                                        .data(format!("Skipped {} events", n)));
                                }
                                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                                    yield Ok(Event::default().event("end").data("channel closed"));
                                    break;
                                }
                            }
                        }
                        result = trace_rx.recv() => {
                            if let Ok(trace_event) = result {
                                let data = serde_json::to_string(&trace_event).unwrap_or_default();
                                yield Ok(Event::default().event("trace_sample").data(data));
                            }
                        }
                    }
                }
            })
        }
        _ => {
            let mut child_rx = state.get_or_create_child_channel(pid).await;
            let mut socket_rx = state.get_or_create_socket_channel(pid).await;

            Box::pin(async_stream::stream! {
                loop {
                    tokio::select! {
                        result = child_rx.recv() => {
                            match result {
                                Ok(event) => {
                                    let data = serde_json::to_string(&event).unwrap_or_default();
                                    yield Ok(Event::default().event("child_process").data(data));
                                }
                                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                                    yield Ok(Event::default()
                                        .event("warning")
                                        .data(format!("Child events: skipped {}", n)));
                                }
                                Err(_) => {
                                    yield Ok(Event::default().event("end").data("child channel closed"));
                                }
                            }
                        }
                        result = socket_rx.recv() => {
                            match result {
                                Ok(event) => {
                                    let data = serde_json::to_string(&event).unwrap_or_default();
                                    yield Ok(Event::default().event("socket_connection").data(data));
                                }
                                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                                    yield Ok(Event::default()
                                        .event("warning")
                                        .data(format!("Socket events: skipped {}", n)));
                                }
                                Err(_) => {
                                    yield Ok(Event::default().event("end").data("socket channel closed"));
                                }
                            }
                        }
                        result = trace_rx.recv() => {
                            if let Ok(trace_event) = result {
                                let data = serde_json::to_string(&trace_event).unwrap_or_default();
                                yield Ok(Event::default().event("trace_sample").data(data));
                            }
                        }
                    }
                }
            })
        }
    };

    Sse::new(sse_stream)
}
