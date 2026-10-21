//! Uninhabited stand-ins for the inflight journal, which needs Linux memfd
//! sealing. They let the request path stay free of platform conditionals.

use std::io;

use crate::RequestId;
use crate::channel::Channel;

#[derive(Clone, Debug)]
pub(crate) enum InflightJournal {}

impl InflightJournal {
    pub(crate) fn reserve(&self) -> io::Result<InflightReservation> {
        match *self {}
    }
}

#[derive(Debug)]
pub(crate) enum InflightReservation {}

impl InflightReservation {
    pub(crate) fn receive(&mut self, _channel: &Channel, _buffer: &mut [u8]) -> nix::Result<usize> {
        match *self {}
    }

    pub(crate) fn publish(self, _unique: RequestId) -> InflightRequest {
        match self {}
    }
}

#[derive(Clone, Debug)]
pub(crate) enum InflightRequest {}

impl InflightRequest {
    pub(crate) fn complete(&self) {
        match *self {}
    }
}
