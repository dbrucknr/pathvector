//! Re-exports [`DaemonClient`] from `pathvector-client` and provides a
//! `MockDaemonClient` test double (available under `#[cfg(test)]`).

pub(crate) use pathvector_client::DaemonClient;

// ── Test double ───────────────────────────────────────────────────────────────

/// Canned-response implementation of [`DaemonClient`] for unit tests.
///
/// Each field holds the value that the corresponding method will return.
/// Methods that do not return data (`set_import_default`, `set_export_default`)
/// return `Ok(())` unconditionally unless `force_error` is set.
#[cfg(test)]
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
}

#[cfg(test)]
impl MockDaemonClient {
    pub fn new() -> Self {
        Self {
            peers: Vec::new(),
            routes: Vec::new(),
            best_route: None,
            candidates: Vec::new(),
            force_error: None,
            import_calls: Vec::new(),
            export_calls: Vec::new(),
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

#[cfg(test)]
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
    ) -> Result<pathvector_client::types::PeerState, pathvector_client::error::ClientError> {
        if let Some(e) = self.check_error() {
            return Err(e);
        }
        self.peers.first().cloned().ok_or_else(|| {
            pathvector_client::error::ClientError::Rpc(tonic::Status::not_found("peer not found"))
        })
    }

    async fn list_routes(
        &mut self,
        _peer: Option<std::net::IpAddr>,
    ) -> Result<Vec<pathvector_client::types::Route>, pathvector_client::error::ClientError> {
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
    ) -> Result<Vec<pathvector_client::types::Route>, pathvector_client::error::ClientError> {
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
}
