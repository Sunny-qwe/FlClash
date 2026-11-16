//! Concord's conditions on a request's or a response's head, and the heads they read.

use std::cell::OnceCell;

use crate::pattern::Pattern;
use crate::text::Field;

const REQUEST_HEAD: &str = "request-head";
const RESPONSE_HEAD: &str = "response-head";

/// Concord's `request-head <re>` and `response-head <re>` after a header or body rewrite's
/// URL: patterns over a head as [crate::headers::head_text] writes it.
#[derive(Debug, Default)]
pub(crate) struct HeadConditions {
    pub(crate) request: Option<Pattern>,
    pub(crate) response: Option<Pattern>,
}

#[derive(Debug)]
pub(crate) enum ConditionError {
    ResponseOnly,
    NoPattern(&'static str),
    Twice(&'static str),
    Pattern(String),
}

impl From<ConditionError> for String {
    fn from(err: ConditionError) -> String {
        match err {
            ConditionError::ResponseOnly => format!("{RESPONSE_HEAD} needs an http-response rule"),
            ConditionError::NoPattern(keyword) => format!("{keyword} needs a pattern"),
            ConditionError::Twice(keyword) => format!("{keyword} is given twice"),
            ConditionError::Pattern(err) => err,
        }
    }
}

impl HeadConditions {
    /// `false` when `keyword` names no condition.
    pub(crate) fn set(
        &mut self,
        keyword: &str,
        pattern: Option<&str>,
        response: bool,
    ) -> Result<bool, ConditionError> {
        let (keyword, slot) = match keyword.to_ascii_lowercase().as_str() {
            REQUEST_HEAD => (REQUEST_HEAD, &mut self.request),
            RESPONSE_HEAD if response => (RESPONSE_HEAD, &mut self.response),
            RESPONSE_HEAD => return Err(ConditionError::ResponseOnly),
            _ => return Ok(false),
        };
        let pattern = pattern.ok_or(ConditionError::NoPattern(keyword))?;
        if slot.is_some() {
            return Err(ConditionError::Twice(keyword));
        }
        *slot = Some(Pattern::new(pattern).map_err(ConditionError::Pattern)?);
        Ok(true)
    }

    /// Reads the conditions from `at` on and returns where the fields after them start.
    pub(crate) fn read(
        fields: &[Field],
        response: bool,
        mut at: usize,
    ) -> Result<(Self, usize), ConditionError> {
        let mut conditions = HeadConditions::default();
        while let Some(keyword) = fields.get(at)
            && conditions.set(
                &keyword.text,
                fields.get(at + 1).map(|field| field.text.as_str()),
                response,
            )?
        {
            at += 2;
        }
        Ok((conditions, at))
    }
}

/// The heads a rule's conditions read, each written at most once and only when a rule
/// whose URL matched asks for it. A head that is not known yet lets its condition pass.
pub(crate) struct Heads<'a> {
    request: Option<&'a dyn Fn() -> String>,
    response: Option<&'a dyn Fn() -> String>,
    request_text: OnceCell<String>,
    response_text: OnceCell<String>,
}

impl<'a> Heads<'a> {
    pub(crate) fn new(
        request: Option<&'a dyn Fn() -> String>,
        response: Option<&'a dyn Fn() -> String>,
    ) -> Self {
        Heads {
            request,
            response,
            request_text: OnceCell::new(),
            response_text: OnceCell::new(),
        }
    }

    pub(crate) fn allow(&self, conditions: &HeadConditions) -> bool {
        self.request_allows(conditions.request.as_ref())
            && pass(
                conditions.response.as_ref(),
                self.response,
                &self.response_text,
            )
    }

    pub(crate) fn request_allows(&self, condition: Option<&Pattern>) -> bool {
        pass(condition, self.request, &self.request_text)
    }
}

fn pass(
    pattern: Option<&Pattern>,
    head: Option<&dyn Fn() -> String>,
    text: &OnceCell<String>,
) -> bool {
    match (pattern, head) {
        (Some(pattern), Some(head)) => pattern.is_match(text.get_or_init(head)),
        _ => true,
    }
}
