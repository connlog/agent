//! Service supervision interface.
//!
//! On Linux the agent runs as a plain systemd foreground process — systemd
//! handles supervision, stdout/stderr capture, and restart policy. Nothing
//! needs to be done here beyond providing a stub so call sites compile.
