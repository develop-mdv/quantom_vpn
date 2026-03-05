use super::auth::AuthFailure;
use super::users::UserRecord;

pub fn ensure_device_limit(user: &UserRecord, active_devices: usize) -> Result<(), AuthFailure> {
    if active_devices >= user.max_devices as usize {
        return Err(AuthFailure::LimitExceeded);
    }
    Ok(())
}

pub fn ensure_session_limit(user: &UserRecord, active_sessions: usize) -> Result<(), AuthFailure> {
    if active_sessions >= user.max_concurrent_sessions as usize {
        return Err(AuthFailure::LimitExceeded);
    }
    Ok(())
}
