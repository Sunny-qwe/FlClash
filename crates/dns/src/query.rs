use std::io;
use std::str::FromStr;

use concord_common::Initiator;
use hickory_proto::op::Message;
use hickory_proto::rr::{Record, RecordType};

use crate::engine::Resolver;
use crate::msg;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuestionView {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

/// `data` is the record's data in presentation format.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordView {
    pub name: String,
    pub rtype: u16,
    pub ttl: u32,
    pub data: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryView {
    pub rcode: u16,
    pub questions: Vec<QuestionView>,
    pub truncated: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub authentic_data: bool,
    pub checking_disabled: bool,
    pub answers: Vec<RecordView>,
    pub authorities: Vec<RecordView>,
    pub additionals: Vec<RecordView>,
}

#[derive(Debug, thiserror::Error)]
pub enum QueryError {
    #[error("invalid query type")]
    Type,
    #[error("invalid name")]
    Name,
    #[error("{0}")]
    Exchange(io::Error),
}

impl Resolver {
    /// One query through the resolver as configured, rules and cache included.
    pub async fn query(&self, name: &str, qtype: &str) -> Result<QueryView, QueryError> {
        let rt = RecordType::from_str(qtype).map_err(|_| QueryError::Type)?;
        let req = msg::build_query(name, rt).ok_or(QueryError::Name)?;
        let resp = self
            .exchange(&req, Initiator::Other)
            .await
            .map_err(QueryError::Exchange)?;
        Ok(view(&resp))
    }
}

fn records(records: &[Record]) -> Vec<RecordView> {
    records
        .iter()
        .map(|record| RecordView {
            name: record.name.to_string(),
            rtype: u16::from(record.record_type()),
            ttl: record.ttl,
            data: record.data.to_string(),
        })
        .collect()
}

fn view(resp: &Message) -> QueryView {
    QueryView {
        rcode: u16::from(resp.metadata.response_code),
        questions: resp
            .queries
            .iter()
            .map(|query| QuestionView {
                name: query.name().to_string(),
                qtype: u16::from(query.query_type()),
                qclass: u16::from(query.query_class()),
            })
            .collect(),
        truncated: resp.metadata.truncation,
        recursion_desired: resp.metadata.recursion_desired,
        recursion_available: resp.metadata.recursion_available,
        authentic_data: resp.metadata.authentic_data,
        checking_disabled: resp.metadata.checking_disabled,
        answers: records(&resp.answers),
        authorities: records(&resp.authorities),
        additionals: records(&resp.additionals),
    }
}
