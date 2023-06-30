//! Utilities for working with events to decide whether they are suitable for
//! use as a RoomInfo::latest_event

use ruma::events::{
    room::message::RoomMessageEventContent, AnySyncMessageLikeEvent, AnySyncTimelineEvent,
    OriginalSyncMessageLikeEvent, SyncMessageLikeEvent,
};

/// Represents a decision about whether an event could be stored as the latest
/// event in a room. Variants starting with Yes indicate that this message could
/// be stored, and provide the inner event information, and those starting with
/// a No indicate that it could not, and give a reason.
#[derive(Debug)]
pub enum PossibleLatestEvent<'a> {
    /// This message is suitable - it is an m.room.message
    YesMessageLike(&'a OriginalSyncMessageLikeEvent<RoomMessageEventContent>),
    // Later: YesState(),
    // Later: YesReaction(),
    /// Not suitable - it's a state event
    NoUnsupportedEventType,
    /// Not suitable - it's not an m.room.message
    NoUnsupportedMessageLikeType,
    /// Not suitable - it's encrypted
    NoEncrypted,
    /// Not suitable - it's redacted (might we want to include these?)
    NoRedacted,
}

/// Decide whether an event could be stored as the latest event in a room.
/// Returns a LatestEvent representing our decision.
pub fn is_suitable_for_latest_event(event: &AnySyncTimelineEvent) -> PossibleLatestEvent<'_> {
    match event {
        // Suitable - we have an m.room.message that was not redacted
        AnySyncTimelineEvent::MessageLike(AnySyncMessageLikeEvent::RoomMessage(
            SyncMessageLikeEvent::Original(message),
        )) => PossibleLatestEvent::YesMessageLike(message),

        // Encrypted events are not suitable
        AnySyncTimelineEvent::MessageLike(AnySyncMessageLikeEvent::RoomEncrypted(_)) => {
            PossibleLatestEvent::NoEncrypted
        }

        // Later, if we support reactions:
        // AnySyncTimelineEvent::MessageLike(AnySyncMessageLikeEvent::Reaction(_))

        // Redacted events are not suitable
        AnySyncTimelineEvent::MessageLike(AnySyncMessageLikeEvent::RoomMessage(
            SyncMessageLikeEvent::Redacted(_),
        )) => PossibleLatestEvent::NoRedacted,

        // MessageLike, but not one of the types we want to show in message previews, so not
        // suitable
        AnySyncTimelineEvent::MessageLike(_) => PossibleLatestEvent::NoUnsupportedMessageLikeType,

        // We don't currently support state events
        AnySyncTimelineEvent::State(_) => PossibleLatestEvent::NoUnsupportedEventType,
    }
}
