use std::sync::Arc;

use anyhow::Context;
use matrix_sdk::{
    notification_settings::{
        NotificationSettings as SdkNotificationSettings,
        RoomNotificationMode as SdkRoomNotificationMode,
    },
    Client as SdkClient,
};
use ruma::{
    events::push_rules::PushRulesEvent,
    push::{PredefinedOverrideRuleId, PredefinedUnderrideRuleId, RuleKind},
    RoomId,
};
use tokio::sync::RwLock;

use crate::error::NotificationSettingsError;

#[derive(Clone, uniffi::Enum)]
pub enum RoomNotificationMode {
    AllMessages,
    MentionsAndKeywordsOnly,
    Mute,
}

impl From<SdkRoomNotificationMode> for RoomNotificationMode {
    fn from(value: SdkRoomNotificationMode) -> Self {
        match value {
            SdkRoomNotificationMode::AllMessages => Self::AllMessages,
            SdkRoomNotificationMode::MentionsAndKeywordsOnly => Self::MentionsAndKeywordsOnly,
            SdkRoomNotificationMode::Mute => Self::Mute,
        }
    }
}

pub trait NotificationSettingsListener: Sync + Send {
    fn notification_settings_did_change(&self);
}

#[derive(Clone, uniffi::Record)]
pub struct RoomNotificationSettings {
    mode: RoomNotificationMode,
    is_default: bool,
}

impl RoomNotificationSettings {
    fn new(mode: RoomNotificationMode, is_default: bool) -> Self {
        RoomNotificationSettings { mode, is_default }
    }
}

#[derive(Clone, uniffi::Enum)]
pub enum PredefinedRuleId {
    /// `.m.rule.call`
    Call,

    /// `.m.rule.encrypted_room_one_to_one`
    EncryptedRoomOneToOne,

    /// `.m.is_room_mention`
    IsRoomMention,

    /// `.m.is_user_mention`
    IsUserMention,

    /// `.m.rule.room_one_to_one`
    RoomOneToOne,

    /// `.m.rule.message`
    Message,

    /// `.m.rule.encrypted`
    Encrypted,
}

#[derive(Clone, uniffi::Object)]
pub struct NotificationSettings {
    sdk_client: SdkClient,
    sdk_notification_settings: Arc<SdkNotificationSettings>,
    delegate: Arc<RwLock<Option<Box<dyn NotificationSettingsListener>>>>,
}

impl NotificationSettings {
    pub(crate) fn new(
        sdk_client: SdkClient,
        sdk_notification_settings: Arc<SdkNotificationSettings>,
    ) -> Self {
        let delegate: Arc<RwLock<Option<Box<dyn NotificationSettingsListener>>>> =
            Arc::new(RwLock::new(None));

        // Listen for PushRulesEvent
        let sdk_notification_settings_clone = sdk_notification_settings.clone();
        let delegate_clone = delegate.clone();
        sdk_client.add_event_handler(move |ev: PushRulesEvent| {
            let sdk_notification_settings = sdk_notification_settings_clone.clone();
            let delegate = delegate_clone.clone();
            async move {
                sdk_notification_settings.set_ruleset(&ev.content.global).await;
                if let Some(delegate) = delegate.read().await.as_ref() {
                    delegate.notification_settings_did_change();
                }
            }
        });

        Self { sdk_client, sdk_notification_settings, delegate }
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl NotificationSettings {
    /// Sets a delegate.
    pub async fn set_delegate(&self, delegate: Option<Box<dyn NotificationSettingsListener>>) {
        *self.delegate.write().await = delegate;
    }

    pub(crate) async fn pushrules_did_changed(&self) {
        // Notifies our delegate
        if let Some(delegate) = self.delegate.read().await.as_ref() {
            delegate.notification_settings_did_change();
        }
    }

    /// Gets the notification mode for a room.
    ///
    /// # Arguments
    ///
    /// * `room_id` - A room ID
    pub async fn get_room_notification_mode(
        &self,
        room_id: String,
    ) -> Result<RoomNotificationSettings, NotificationSettingsError> {
        let parsed_room_id = RoomId::parse(&room_id)
            .map_err(|_e| NotificationSettingsError::InvalidRoomId(room_id))?;
        // Get the current user defined mode for this room
        if let Some(mode) = self
            .sdk_notification_settings
            .get_user_defined_room_notification_mode(&parsed_room_id)
            .await
        {
            return Ok(RoomNotificationSettings::new(mode.into(), false));
        }

        // If the user didn't defined a notification mode, return the default one for
        // this room
        let room = self
            .sdk_client
            .get_room(&parsed_room_id)
            .context("Room not found")
            .map_err(|_| NotificationSettingsError::RoomNotFound)?;

        let is_encrypted = room.is_encrypted().await.unwrap_or(false);
        let members_count = room.joined_members_count();

        let mode = self
            .sdk_notification_settings
            .get_default_room_notification_mode(is_encrypted, members_count)
            .await;
        Ok(RoomNotificationSettings::new(mode.into(), true))
    }

    /// Gets the default notification mode for a room.
    ///
    /// # Arguments
    ///
    /// * `is_encrypted` - A `bool` indicating whether the room is encrypted
    /// * `members_count` - The number of members in the room
    pub async fn get_default_room_notification_mode(
        &self,
        is_encrypted: bool,
        members_count: u64,
    ) -> RoomNotificationMode {
        let mode = self
            .sdk_notification_settings
            .get_default_room_notification_mode(is_encrypted, members_count)
            .await;
        mode.into()
    }

    /// Sets the notification mode for a room.
    ///
    /// # Arguments
    ///
    /// * `room_id` - A room ID
    /// * `mode` - A `RoomNotificationMode`
    pub async fn set_room_notification_mode(
        &self,
        room_id: String,
        mode: RoomNotificationMode,
    ) -> Result<(), NotificationSettingsError> {
        let mode = match mode {
            RoomNotificationMode::AllMessages => SdkRoomNotificationMode::AllMessages,
            RoomNotificationMode::MentionsAndKeywordsOnly => {
                SdkRoomNotificationMode::MentionsAndKeywordsOnly
            }
            RoomNotificationMode::Mute => SdkRoomNotificationMode::Mute,
        };
        let parsed_room_id = RoomId::parse(&room_id)
            .map_err(|_e| NotificationSettingsError::InvalidRoomId(room_id))?;

        self.sdk_notification_settings.set_room_notification_mode(&parsed_room_id, mode).await?;
        Ok(())
    }

    /// Restores the default notification mode for a room
    ///
    /// # Arguments
    ///
    /// * `room_id` - A room ID
    pub async fn restore_default_room_notification_mode(
        &self,
        room_id: String,
    ) -> Result<(), NotificationSettingsError> {
        let parsed_room_id = RoomId::parse(&room_id)
            .map_err(|_e| NotificationSettingsError::InvalidRoomId(room_id))?;
        self.sdk_notification_settings.delete_user_defined_room_rules(&parsed_room_id).await?;
        Ok(())
    }

    /// Get whether some enabled keyword rules exist.
    pub async fn contains_keywords_rules(&self) -> bool {
        self.sdk_notification_settings.contains_keyword_rules().await
    }

    /// Unmute a room.
    ///     
    /// # Arguments
    ///
    /// * `room_id` - A room ID
    pub async fn unmute_room(&self, room_id: String) -> Result<(), NotificationSettingsError> {
        let parsed_room_id = RoomId::parse(&room_id)
            .map_err(|_e| NotificationSettingsError::InvalidRoomId(room_id))?;
        self.sdk_notification_settings.unmute_room(&parsed_room_id).await?;
        Ok(())
    }

    /// Get whether a rule is enabled.
    ///
    /// # Arguments
    ///
    /// * `rule_id` - A `PredefinedRuleId`
    pub async fn is_push_rule_enabled(
        &self,
        rule_id: PredefinedRuleId,
    ) -> Result<bool, NotificationSettingsError> {
        let enabled = match rule_id {
            PredefinedRuleId::Call => {
                self.sdk_notification_settings
                    .is_push_rule_enabled(
                        RuleKind::Underride,
                        PredefinedUnderrideRuleId::Call.to_string(),
                    )
                    .await
            }
            PredefinedRuleId::EncryptedRoomOneToOne => {
                self.sdk_notification_settings
                    .is_push_rule_enabled(
                        RuleKind::Underride,
                        PredefinedUnderrideRuleId::EncryptedRoomOneToOne.to_string(),
                    )
                    .await
            }
            PredefinedRuleId::IsRoomMention => {
                self.sdk_notification_settings
                    .is_push_rule_enabled(
                        RuleKind::Override,
                        PredefinedOverrideRuleId::IsRoomMention.to_string(),
                    )
                    .await
            }
            PredefinedRuleId::IsUserMention => {
                self.sdk_notification_settings
                    .is_push_rule_enabled(
                        RuleKind::Override,
                        PredefinedOverrideRuleId::IsUserMention.to_string(),
                    )
                    .await
            }
            PredefinedRuleId::RoomOneToOne => {
                self.sdk_notification_settings
                    .is_push_rule_enabled(
                        RuleKind::Underride,
                        PredefinedUnderrideRuleId::RoomOneToOne.to_string(),
                    )
                    .await
            }
            PredefinedRuleId::Message => {
                self.sdk_notification_settings
                    .is_push_rule_enabled(
                        RuleKind::Underride,
                        PredefinedUnderrideRuleId::Message.to_string(),
                    )
                    .await
            }
            PredefinedRuleId::Encrypted => {
                self.sdk_notification_settings
                    .is_push_rule_enabled(
                        RuleKind::Underride,
                        PredefinedUnderrideRuleId::Encrypted.to_string(),
                    )
                    .await
            }
        };
        Ok(enabled?)
    }

    /// Set whether a predefined rule is enabled.
    ///
    /// # Arguments
    ///
    /// * `rule_id` - A `PredefinedRuleId`
    /// * `enabled` - A `bool` indicating whether the rule should be activated
    pub async fn set_push_rule_enabled(
        &self,
        rule_id: PredefinedRuleId,
        enabled: bool,
    ) -> Result<(), NotificationSettingsError> {
        match rule_id {
            PredefinedRuleId::Call => {
                self.sdk_notification_settings
                    .set_push_rule_enabled(
                        RuleKind::Underride,
                        PredefinedUnderrideRuleId::Call.to_string(),
                        enabled,
                    )
                    .await?
            }
            PredefinedRuleId::Encrypted => {
                self.sdk_notification_settings
                    .set_push_rule_enabled(
                        RuleKind::Underride,
                        PredefinedUnderrideRuleId::Encrypted.to_string(),
                        enabled,
                    )
                    .await?
            }
            PredefinedRuleId::EncryptedRoomOneToOne => {
                self.sdk_notification_settings
                    .set_push_rule_enabled(
                        RuleKind::Underride,
                        PredefinedUnderrideRuleId::EncryptedRoomOneToOne.to_string(),
                        enabled,
                    )
                    .await?
            }
            PredefinedRuleId::IsRoomMention => {
                self.sdk_notification_settings
                    .set_push_rule_enabled(
                        RuleKind::Override,
                        PredefinedOverrideRuleId::IsRoomMention.to_string(),
                        enabled,
                    )
                    .await?
            }
            PredefinedRuleId::IsUserMention => {
                self.sdk_notification_settings
                    .set_push_rule_enabled(
                        RuleKind::Override,
                        PredefinedOverrideRuleId::IsUserMention.to_string(),
                        enabled,
                    )
                    .await?
            }
            PredefinedRuleId::Message => {
                self.sdk_notification_settings
                    .set_push_rule_enabled(
                        RuleKind::Underride,
                        PredefinedUnderrideRuleId::Message.to_string(),
                        enabled,
                    )
                    .await?
            }
            PredefinedRuleId::RoomOneToOne => {
                self.sdk_notification_settings
                    .set_push_rule_enabled(
                        RuleKind::Underride,
                        PredefinedUnderrideRuleId::RoomOneToOne.to_string(),
                        enabled,
                    )
                    .await?
            }
        };
        Ok(())
    }
}
