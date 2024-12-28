use std::fmt::Display;

#[derive(Debug)]
pub enum Errors<'a> {
    EmptyBuffer(&'a str),
    ProcessNotFound,
}

impl Display for Errors<'_> {
    fn fmt(&'_ self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Errors::EmptyBuffer(error) => error,
            Errors::ProcessNotFound => "Process not found!",
        };
        write!(f, "Error: {message:?}")
    }
}