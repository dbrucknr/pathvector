//! Re-exports [`DaemonClient`] from `pathvector-client`.

pub(crate) use pathvector_client::DaemonClient;

#[cfg(test)]
pub(crate) mod tests {
    use futures::StreamExt as _;
    use pathvector_client::error::ClientError;

    use super::DaemonClient;

    // ── Test double ───────────────────────────────────────────────────────────

    /// Canned-response implementation of [`DaemonClient`] for unit tests.
    ///
    /// Each field holds the value that the corresponding method will return.
    /// Methods that do not return data (`set_import_default`, `set_export_default`)
    /// return `Ok(())` unconditionally unless `force_error` is set.
    ///
    /// For streaming methods (`watch_peers`, `watch_routes`), provide event
    /// sequences via `peer_events` and `route_events`. Each call drains the next
    /// batch from the front of the queue. An empty queue returns an empty stream.
    pub(crate) struct MockDaemonClient {
        pub peers: Vec<pathvector_client::types::PeerState>,
        pub routes: Vec<pathvector_client::types::Route>,
        pub best_route: Option<pathvector_client::types::Route>,
        pub candidates: Vec<pathvector_client::types::Route>,
        /// When `Some`, every method returns this error instead of its normal value.
        pub force_error: Option<pathvector_client::error::ClientError>,
        /// Recorded calls to `set_import_default` — `(peer, accept)`.
        pub import_calls: Vec<(String, bool)>,
        /// Recorded calls to `set_export_default` — `(peer, accept)`.
        pub export_calls: Vec<(String, bool)>,
        /// Queued batches for `watch_peers`. Each `watch_peers` call drains one batch.
        pub peer_events: std::collections::VecDeque<
            Vec<Result<pathvector_client::types::PeerEvent, pathvector_client::error::ClientError>>,
        >,
        /// Queued batches for `watch_routes`. Each `watch_routes` call drains one batch.
        pub route_events: std::collections::VecDeque<
            Vec<
                Result<pathvector_client::types::RouteEvent, pathvector_client::error::ClientError>,
            >,
        >,
    }

    impl MockDaemonClient {
        pub(crate) fn new() -> Self {
            Self {
                peers: Vec::new(),
                routes: Vec::new(),
                best_route: None,
                candidates: Vec::new(),
                force_error: None,
                import_calls: Vec::new(),
                export_calls: Vec::new(),
                peer_events: std::collections::VecDeque::new(),
                route_events: std::collections::VecDeque::new(),
            }
        }

        fn check_error(&self) -> Option<pathvector_client::error::ClientError> {
            use pathvector_client::error::ClientError;
            self.force_error.as_ref().map(|e| match e {
                ClientError::Rpc(s) => ClientError::Rpc(tonic::Status::new(s.code(), s.message())),
                ClientError::Convert(c) => ClientError::Rpc(tonic::Status::internal(c.to_string())),
            })
        }
    }

    impl DaemonClient for MockDaemonClient {
        async fn list_peers(
            &mut self,
        ) -> Result<Vec<pathvector_client::types::PeerState>, pathvector_client::error::ClientError>
        {
            if let Some(e) = self.check_error() {
                return Err(e);
            }
            Ok(self.peers.clone())
        }

        async fn get_peer(
            &mut self,
            _address: std::net::IpAddr,
        ) -> Result<pathvector_client::types::PeerState, pathvector_client::error::ClientError>
        {
            if let Some(e) = self.check_error() {
                return Err(e);
            }
            self.peers.first().cloned().ok_or_else(|| {
                pathvector_client::error::ClientError::Rpc(tonic::Status::not_found(
                    "peer not found",
                ))
            })
        }

        async fn list_routes(
            &mut self,
            _peer: Option<std::net::IpAddr>,
        ) -> Result<Vec<pathvector_client::types::Route>, pathvector_client::error::ClientError>
        {
            if let Some(e) = self.check_error() {
                return Err(e);
            }
            Ok(self.routes.clone())
        }

        async fn get_best_route(
            &mut self,
            _prefix: &str,
        ) -> Result<Option<pathvector_client::types::Route>, pathvector_client::error::ClientError>
        {
            if let Some(e) = self.check_error() {
                return Err(e);
            }
            Ok(self.best_route.clone())
        }

        async fn list_candidates(
            &mut self,
            _prefix: &str,
        ) -> Result<Vec<pathvector_client::types::Route>, pathvector_client::error::ClientError>
        {
            if let Some(e) = self.check_error() {
                return Err(e);
            }
            Ok(self.candidates.clone())
        }

        async fn set_import_default(
            &mut self,
            peer: &str,
            accept: bool,
        ) -> Result<(), pathvector_client::error::ClientError> {
            if let Some(e) = self.check_error() {
                return Err(e);
            }
            self.import_calls.push((peer.to_owned(), accept));
            Ok(())
        }

        async fn set_export_default(
            &mut self,
            peer: &str,
            accept: bool,
        ) -> Result<(), pathvector_client::error::ClientError> {
            if let Some(e) = self.check_error() {
                return Err(e);
            }
            self.export_calls.push((peer.to_owned(), accept));
            Ok(())
        }

        async fn originate_route(
            &mut self,
            _params: pathvector_client::types::OriginateRouteParams,
        ) -> Result<(), pathvector_client::error::ClientError> {
            if let Some(e) = self.check_error() {
                return Err(e);
            }
            Ok(())
        }

        async fn originate_routes(
            &mut self,
            routes: Vec<pathvector_client::types::OriginateRouteParams>,
        ) -> Result<u32, pathvector_client::error::ClientError> {
            if let Some(e) = self.check_error() {
                return Err(e);
            }
            Ok(u32::try_from(routes.len()).unwrap_or(u32::MAX))
        }

        async fn withdraw_originated_route(
            &mut self,
            _prefix: &str,
        ) -> Result<(), pathvector_client::error::ClientError> {
            if let Some(e) = self.check_error() {
                return Err(e);
            }
            Ok(())
        }

        async fn withdraw_originated_routes(
            &mut self,
            prefixes: Vec<String>,
        ) -> Result<u32, pathvector_client::error::ClientError> {
            if let Some(e) = self.check_error() {
                return Err(e);
            }
            Ok(u32::try_from(prefixes.len()).unwrap_or(u32::MAX))
        }

        async fn list_originated_routes(
            &mut self,
        ) -> Result<Vec<pathvector_client::types::Route>, pathvector_client::error::ClientError>
        {
            if let Some(e) = self.check_error() {
                return Err(e);
            }
            Ok(vec![])
        }

        async fn watch_routes(
            &mut self,
            _peer: Option<&str>,
        ) -> Result<
            pathvector_client::BoxStream<pathvector_client::types::RouteEvent>,
            pathvector_client::error::ClientError,
        > {
            let events = self.route_events.pop_front().unwrap_or_default();
            Ok(Box::pin(futures::stream::iter(events)))
        }

        async fn watch_peers(
            &mut self,
        ) -> Result<
            pathvector_client::BoxStream<pathvector_client::types::PeerEvent>,
            pathvector_client::error::ClientError,
        > {
            let events = self.peer_events.pop_front().unwrap_or_default();
            Ok(Box::pin(futures::stream::iter(events)))
        }
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    fn rpc_err() -> ClientError {
        ClientError::Rpc(tonic::Status::unavailable("no daemon"))
    }

    /// `list_routes` returns `Err` when `force_error` is set.
    #[tokio::test]
    async fn list_routes_propagates_error() {
        let mut mock = MockDaemonClient::new();
        mock.force_error = Some(rpc_err());
        let result = mock.list_routes(None).await;
        assert!(result.is_err());
    }

    /// `watch_routes` returns the queued event batch and drains it.
    #[tokio::test]
    async fn watch_routes_yields_queued_events() {
        use pathvector_client::types::{RouteEvent, RouteEventType};
        let mut mock = MockDaemonClient::new();
        let event = RouteEvent {
            event_type: RouteEventType::EndInitial,
            route: None,
            withdrawn_prefix: None,
        };
        mock.route_events.push_back(vec![Ok(event)]);

        let mut stream = mock.watch_routes(None).await.unwrap();
        assert!(stream.next().await.is_some());
        assert!(stream.next().await.is_none());
    }

    /// `watch_routes` with an empty queue returns an empty stream.
    #[tokio::test]
    async fn watch_routes_empty_queue_returns_empty_stream() {
        let mut mock = MockDaemonClient::new();
        let mut stream = mock.watch_routes(None).await.unwrap();
        assert!(stream.next().await.is_none());
    }

    /// `watch_peers` returns the queued event batch and drains it.
    #[tokio::test]
    async fn watch_peers_yields_queued_events() {
        use pathvector_client::types::{PeerEvent, PeerEventType};
        let mut mock = MockDaemonClient::new();
        let event = PeerEvent {
            event_type: PeerEventType::EndInitial,
            peer: None,
        };
        mock.peer_events.push_back(vec![Ok(event)]);

        let mut stream = mock.watch_peers().await.unwrap();
        assert!(stream.next().await.is_some());
        assert!(stream.next().await.is_none());
    }

    /// `watch_peers` with an empty queue returns an empty stream.
    #[tokio::test]
    async fn watch_peers_empty_queue_returns_empty_stream() {
        let mut mock = MockDaemonClient::new();
        let mut stream = mock.watch_peers().await.unwrap();
        assert!(stream.next().await.is_none());
    }
}
