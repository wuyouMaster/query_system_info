use axum::extract::{Path, Query, State};
use axum::response::sse::{Event, Sse};
use futures::stream::{self, Stream};
use serde::Deserialize;
use std::convert::Infallible;
use std::pin::Pin;
use std::time::Duration;
use tokio::task;

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
    Query(params): Query<StreamParams>,
) -> Sse<BoxSseStream> {
    let interval_ms = params.interval.unwrap_or(1000);
    let interval = Duration::from_millis(interval_ms);

    let sse_stream = stream::unfold((), move |()| async move {
        let sample_duration = Duration::from_millis(200);
        let result = task::spawn_blocking(move || {
            query_system_info::cpu::get_cpu_usage(sample_duration)
        })
        .await;

        let event = match result {
            Ok(Ok(usage)) => {
                let data = serde_json::to_string(&usage).unwrap_or_default();
                Ok(Event::default().event("cpu_usage").data(data))
            }
            Ok(Err(e)) => Ok(Event::default().event("error").data(e.to_string())),
            Err(e) => Ok(Event::default().event("error").data(e.to_string())),
        };

        tokio::time::sleep(interval).await;
        Some((event, ()))
    });

    Sse::new(Box::pin(sse_stream))
}

pub async fn process_tracker(
    Path(pid): Path<u32>,
    Query(params): Query<ProcessStreamParams>,
    State(state): State<AppState>,
) -> Sse<BoxSseStream> {
    let stream_type = params.stream_type.unwrap_or_else(|| "all".to_string());

    let sse_stream: BoxSseStream = match stream_type.as_str() {
        "children" => {
            let mut rx = state.get_or_create_child_channel(pid).await;
            Box::pin(async_stream::stream! {
                loop {
                    match rx.recv().await {
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
            })
        }
        "sockets" => {
            let mut rx = state.get_or_create_socket_channel(pid).await;
            Box::pin(async_stream::stream! {
                loop {
                    match rx.recv().await {
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
                    }
                }
            })
        }
    };

    Sse::new(sse_stream)
}
