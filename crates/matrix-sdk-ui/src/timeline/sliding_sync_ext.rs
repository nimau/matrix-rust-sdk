// Copyright 2023 The Matrix.org Foundation C.I.C.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use async_trait::async_trait;
use imbl::Vector;
use indexmap::IndexMap;
use matrix_sdk::SlidingSyncRoom;
use matrix_sdk_base::deserialized_responses::SyncTimelineEvent;
use ruma::events::AnyMessageLikeEvent;
use tracing::{error, instrument, warn};

use super::{
    event_item::{RemoteEventOrigin, RemoteEventTimelineItem},
    EventTimelineItem, Message, Timeline, TimelineBuilder, TimelineDetails, TimelineItemContent,
};

#[async_trait]
pub trait SlidingSyncRoomExt {
    /// Get a `Timeline` for this room.
    async fn timeline(&self) -> Option<Timeline>;

    /// Get the latest timeline item of this room, if it is already cached.
    ///
    /// Use `Timeline::latest_event` instead if you already have a timeline for
    /// this `SlidingSyncRoom`.
    fn latest_timeline_item(&self) -> Option<EventTimelineItem>;
}

#[async_trait]
impl SlidingSyncRoomExt for SlidingSyncRoom {
    async fn timeline(&self) -> Option<Timeline> {
        Some(sliding_sync_timeline_builder(self)?.track_read_marker_and_receipts().build().await)
    }

    /// Get a timeline item representing the latest event in this room.
    /// This method wraps latest_event, converting the event into an
    /// EventTimelineItem.
    #[instrument(skip_all)]
    fn latest_timeline_item(&self) -> Option<EventTimelineItem> {
        self.latest_event().and_then(|e| wrap(self, e))
    }
}

fn sliding_sync_timeline_builder(room: &SlidingSyncRoom) -> Option<TimelineBuilder> {
    let room_id = room.room_id();
    match room.client().get_room(room_id) {
        Some(r) => Some(Timeline::builder(&r).events(room.prev_batch(), room.timeline_queue())),
        None => {
            error!(?room_id, "Room not found in client. Can't provide a timeline for it");
            None
        }
    }
}

/// Wrap a low-level event from a sync into a high-level EventTimelineItem,
/// ready to be used in the message preview in a client.
fn wrap(room: &SlidingSyncRoom, sync_event: SyncTimelineEvent) -> Option<EventTimelineItem> {
    let raw_sync_event = sync_event.event;

    let encryption_info = sync_event.encryption_info;

    // If the supplied event is not a MessageLikeEvent, return None.
    // In future, we will want to handle reactions, so will need to do more here.
    let message_like = raw_sync_event.deserialize_as::<AnyMessageLikeEvent>().ok()?;

    let timestamp = message_like.origin_server_ts();
    let sender = message_like.sender().to_owned();
    let event_id = message_like.event_id().to_owned();
    let is_own = room.client().user_id().map(|uid| uid == sender).unwrap_or(false);

    // If we don't (yet) know how to handle this type of message, return None here.
    // If we do, convert it into a TimelineItemContent.
    let item_content = wrap_content(message_like)?;

    // We don't currently bundle any reactions with the main event. This could
    // conceivably be wanted in the message preview in future.
    let reactions = IndexMap::new();

    // The message preview probably never needs read receipts.
    let read_receipts = IndexMap::new();

    // Being highlighted is _probably_ not relevant to the message preview.
    let is_highlighted = false;

    // We may need this, depending on how we are going to display edited messages in
    // previews.
    let latest_edit_json = None;

    // Probably the origin of the event doesn't matter for the preview.
    let origin = RemoteEventOrigin::Sync;

    let event_kind = RemoteEventTimelineItem {
        event_id,
        reactions,
        read_receipts,
        is_own,
        is_highlighted,
        encryption_info,
        original_json: raw_sync_event,
        latest_edit_json,
        origin,
    }
    .into();

    // This will probably be required for message previews, but if so we need to
    // cache the contents of a Profile struct inside RoomInfo similar to how we
    // are caching the event.
    let sender_profile = TimelineDetails::Unavailable;

    Some(EventTimelineItem::new(sender, sender_profile, timestamp, item_content, event_kind))
}

fn wrap_content(message_like: AnyMessageLikeEvent) -> Option<TimelineItemContent> {
    match message_like {
        AnyMessageLikeEvent::RoomMessage(ref m) => {
            let event_content = m.as_original().unwrap().content.clone();

            // If this message is a reply, we would look up in this list the message it was
            // replying to. Since we probably won't show this in the message preview,
            // it's probably OK to supply an empty list here.
            // Message::from_event marks the original event as Unavailable if it can't be
            // found inside the timeline_items.
            let timeline_items = Vector::new();

            Some(TimelineItemContent::Message(Message::from_event(
                event_content,
                message_like.relations(),
                &timeline_items,
            )))
        }
        // TODO: other types of message need to be represented in message previews too.
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use matrix_sdk::{config::RequestConfig, Client, ClientBuilder, SlidingSyncRoom};
    use matrix_sdk_base::{deserialized_responses::SyncTimelineEvent, BaseClient, SessionMeta};
    use matrix_sdk_test::async_test;
    use ruma::{
        api::{client::sync::sync_events::v4, MatrixVersion},
        device_id,
        events::room::message::{MessageFormat, MessageType},
        room_id,
        serde::Raw,
        user_id, RoomId, UInt, UserId,
    };
    use serde_json::json;

    use crate::timeline::{SlidingSyncRoomExt, TimelineDetails};

    #[async_test]
    async fn initially_latest_message_event_is_none() {
        // Given a room with no latest event
        let room_id = room_id!("!r:x.uk").to_owned();
        let client = logged_in_client(None).await;
        let room = SlidingSyncRoom::new(client, room_id, v4::SlidingSyncRoom::new(), Vec::new());

        // When we ask for the latest event, it is None
        assert!(room.latest_timeline_item().is_none());
    }

    #[async_test]
    async fn latest_message_event_is_wrapped_as_a_timeline_item() {
        // Given a room exists, and an event came in through a sync
        let room_id = room_id!("!r:x.uk");
        let user_id = user_id!("@s:o.uk");
        let client = logged_in_client(None).await;
        let event = message_event(room_id, user_id, "**My msg**", "<b>My msg</b>", 122343);
        process_event_via_sync(room_id, event, &client).await;

        // When we ask for the latest event in the room
        let room = SlidingSyncRoom::new(
            client.clone(),
            room_id.to_owned(),
            v4::SlidingSyncRoom::new(),
            Vec::new(),
        );
        let actual = room.latest_timeline_item().unwrap();

        // Then it is wrapped as an EventTimelineItem
        assert_eq!(actual.sender, user_id);
        assert_matches!(actual.sender_profile, TimelineDetails::Unavailable);
        assert_eq!(actual.timestamp.0, UInt::new(122343).unwrap());
        if let MessageType::Text(txt) = actual.content.as_message().unwrap().msgtype() {
            assert_eq!(txt.body, "**My msg**");
            let formatted = txt.formatted.as_ref().unwrap();
            assert_eq!(formatted.format, MessageFormat::Html);
            assert_eq!(formatted.body, "<b>My msg</b>");
        } else {
            panic!("Unexpected message type");
        }
    }

    async fn process_event_via_sync(room_id: &RoomId, event: SyncTimelineEvent, client: &Client) {
        let mut room = v4::SlidingSyncRoom::new();
        room.timeline.push(event.event);
        let response = response_with_room(room_id, room).await;
        client.process_sliding_sync(&response).await.unwrap();
    }

    fn message_event(
        room_id: &RoomId,
        user_id: &UserId,
        body: &str,
        formatted_body: &str,
        ts: u64,
    ) -> SyncTimelineEvent {
        SyncTimelineEvent::new(
            Raw::from_json_string(
                json!({
                    "event_id": "$eventid6",
                    "sender": user_id,
                    "origin_server_ts": ts,
                    "type": "m.room.message",
                    "room_id": room_id.to_string(),
                    "content": {
                        "body": body,
                        "format": "org.matrix.custom.html",
                        "formatted_body": formatted_body,
                        "msgtype": "m.text"
                    },
                })
                .to_string(),
            )
            .unwrap(),
        )
    }

    async fn response_with_room(room_id: &RoomId, room: v4::SlidingSyncRoom) -> v4::Response {
        let mut response = v4::Response::new("6".to_owned());
        response.rooms.insert(room_id.to_owned(), room);
        response
    }

    /// Copied from matrix_sdk_base::sliding_sync::test
    async fn logged_in_client(homeserver_url: Option<String>) -> Client {
        let base_client = BaseClient::new();
        base_client
            .set_session_meta(SessionMeta {
                user_id: user_id!("@u:e.uk").to_owned(),
                device_id: device_id!("XYZ").to_owned(),
            })
            .await
            .expect("Failed to set session meta");

        test_client_builder(homeserver_url)
            .request_config(RequestConfig::new().disable_retry())
            .base_client(base_client)
            .build()
            .await
            .unwrap()
    }

    fn test_client_builder(homeserver_url: Option<String>) -> ClientBuilder {
        let homeserver = homeserver_url.as_deref().unwrap_or("http://localhost:1234");
        Client::builder().homeserver_url(homeserver).server_versions([MatrixVersion::V1_0])
    }
}
