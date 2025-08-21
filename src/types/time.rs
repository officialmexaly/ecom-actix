use serde::{Deserialize, Serialize};
use chrono::{Weekday, NaiveTime};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct TimeWindow {
    pub days_of_week: Vec<Weekday>,
    pub start_time: NaiveTime,
    pub end_time: NaiveTime,
    pub timezone: String,
    pub exceptions: Vec<DateException>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct DateException {
    pub date: chrono::NaiveDate,
    pub exception_type: ExceptionType,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ExceptionType {
    Holiday,      // Access denied
    Emergency,    // Access always allowed
    Maintenance,  // Limited access
}