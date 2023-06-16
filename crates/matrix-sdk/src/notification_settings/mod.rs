//! High-level push notification settings API

use std::sync::Arc;

use ruma::{
    api::client::push::{delete_pushrule, set_pushrule, set_pushrule_enabled, RuleScope},
    push::{RuleKind, Ruleset},
    RoomId,
};
use tokio::sync::RwLock;

use self::rules::{Command, Rules};

mod rules;

use crate::{error::NotificationSettingsError, Client, Result};

/// Enum representing the push notification modes for a room.
#[derive(Debug, Clone, PartialEq)]
pub enum RoomNotificationMode {
    /// Receive notifications for all messages.
    AllMessages,
    /// Receive notifications for mentions and keywords only.
    MentionsAndKeywordsOnly,
    /// Do not receive any notifications.
    Mute,
}

/// A high-level API to manage the client owner's push notification settings.
#[derive(Debug, Clone)]
pub struct NotificationSettings {
    /// The underlying HTTP client.
    client: Client,
    /// Owner's account push rules. They will be updated on sync.
    ruleset: Arc<RwLock<Ruleset>>,
}

impl NotificationSettings {
    /// Build a new `NotificationSettings``
    ///
    /// # Arguments
    ///
    /// * `client` - A `Client` used to perform API calls
    pub fn new(client: Client, ruleset: Ruleset) -> Self {
        let ruleset = Arc::new(RwLock::new(ruleset));
        Self { client, ruleset }
    }

    /// Set the ruleset
    ///
    /// # Arguments
    ///
    /// * `ruleset` - A `Ruleset` containing account's owner push rules
    pub async fn set_ruleset(&self, ruleset: &Ruleset) {
        *self.ruleset.write().await = ruleset.clone();
    }

    /// Gets all user defined rules matching a given `room_id`.
    ///
    /// # Arguments
    ///
    /// * `room_id` - A `RoomId`
    async fn get_custom_rules_for_room(&self, room_id: &RoomId) -> Vec<(RuleKind, String)> {
        let ruleset = self.ruleset.read().await;
        Rules::new(ruleset.clone()).get_custom_rules_for_room(room_id)
    }

    /// Gets the user defined push notification mode for a room.
    ///
    /// # Arguments
    ///
    /// * `room_id` - A `RoomId`
    pub async fn get_user_defined_room_notification_mode(
        &self,
        room_id: &RoomId,
    ) -> Option<RoomNotificationMode> {
        let ruleset = self.ruleset.read().await;
        Rules::new(ruleset.clone()).get_user_defined_room_notification_mode(room_id)
    }

    /// Gets the default notification mode for a room.
    ///
    /// # Arguments
    ///
    /// * `is_encrypted` - `true` if the room is encrypted
    /// * `members_count` - the room members count
    pub async fn get_default_room_notification_mode(
        &self,
        is_encrypted: bool,
        members_count: u64,
    ) -> RoomNotificationMode {
        let ruleset = self.ruleset.read().await;
        Rules::new(ruleset.clone()).get_default_room_notification_mode(is_encrypted, members_count)
    }

    /// Get whether the given ruleset contains some enabled keywords rules.
    pub async fn contains_keyword_rules(&self) -> bool {
        let ruleset = self.ruleset.read().await;
        Rules::new(ruleset.clone()).contains_keyword_rules()
    }

    /// Get whether a rule is enabled.
    ///
    /// # Arguments
    ///
    /// * `kind` - A `RuleKind`
    /// * `rule_id` - A rule ID
    pub async fn is_push_rule_enabled(
        &self,
        kind: RuleKind,
        rule_id: String,
    ) -> Result<bool, NotificationSettingsError> {
        let ruleset = self.ruleset.read().await;
        Rules::new(ruleset.clone()).is_enabled(kind, rule_id)
    }

    /// Set whether an rule is enabled.
    ///
    /// # Arguments
    ///
    /// * `kind` - A `RuleKind`
    /// * `rule_id` - A rule ID
    /// * `enabled` - A `bool` indicating whether the rule should be activated
    pub async fn set_push_rule_enabled(
        &self,
        kind: RuleKind,
        rule_id: String,
        enabled: bool,
    ) -> Result<(), NotificationSettingsError> {
        let ruleset = &mut *self.ruleset.write().await;

        let mut rules = Rules::new(ruleset.clone());
        let commands = rules
            .set_enabled(RuleScope::Global, kind, rule_id, enabled)
            .map_err(|_| NotificationSettingsError::UnableToUpdatePushRule)?;
        self.execute_commands(commands)
            .await
            .map_err(|_| NotificationSettingsError::UnableToUpdatePushRule)?;
        *ruleset = rules.ruleset;

        Ok(())
    }

    /// Sets the notification mode for a room.
    ///
    /// # Arguments
    ///
    /// * `room_id` - A `RoomId`
    /// * `mode` - The `RoomNotificationMode` to set
    pub async fn set_room_notification_mode(
        &self,
        room_id: &RoomId,
        mode: RoomNotificationMode,
    ) -> Result<(), NotificationSettingsError> {
        // Get the current mode
        let current_mode = self.get_user_defined_room_notification_mode(room_id).await;

        match (current_mode, mode) {
            // from `None` to `AllMessages`
            (None, RoomNotificationMode::AllMessages) => {
                self.insert_room_rule(RuleKind::Room, room_id, true).await?;
            }
            // from `MentionsAndKeywordsOnly`to `AllMessages`
            (
                Some(RoomNotificationMode::MentionsAndKeywordsOnly),
                RoomNotificationMode::AllMessages,
            ) => {
                // Insert the rule before deleting the other custom rules to obtain the correct
                // mode in the next sync response.
                let current_custom_rules = self.get_custom_rules_for_room(room_id).await;
                self.insert_room_rule(RuleKind::Room, room_id, true).await?;
                self.delete_rules(
                    current_custom_rules,
                    vec![(RuleKind::Room, room_id.to_string())],
                )
                .await?;
            }
            // from `Mute` to `AllMessages`
            (Some(RoomNotificationMode::Mute), RoomNotificationMode::AllMessages) => {
                // Insert the rule before deleting the other custom rules to obtain the correct
                // mode in the next sync response.
                let current_custom_rules = self.get_custom_rules_for_room(room_id).await;
                self.insert_room_rule(RuleKind::Room, room_id, true).await?;
                self.delete_rules(current_custom_rules, vec![]).await?;
            }
            // from `None` to `MentionsAndKeywordsOnly`
            (None, RoomNotificationMode::MentionsAndKeywordsOnly) => {
                self.insert_room_rule(RuleKind::Room, room_id, false).await?;
            }
            // from `AllMessages` to `MentionsAndKeywordsOnly`
            (
                Some(RoomNotificationMode::AllMessages),
                RoomNotificationMode::MentionsAndKeywordsOnly,
            ) => {
                // Insert the rule before deleting the other custom rules to obtain the correct
                // mode in the next sync response.
                let current_custom_rules = self.get_custom_rules_for_room(room_id).await;
                self.insert_room_rule(RuleKind::Room, room_id, false).await?;
                self.delete_rules(
                    current_custom_rules,
                    vec![(RuleKind::Room, room_id.to_string())],
                )
                .await?;
            }
            // from `Mute`to `MentionsAndKeywordsOnly`
            (Some(RoomNotificationMode::Mute), RoomNotificationMode::MentionsAndKeywordsOnly) => {
                // Insert the rule before deleting the other custom rules to obtain the correct
                // mode in the next sync response.
                let current_custom_rules = self.get_custom_rules_for_room(room_id).await;
                self.insert_room_rule(RuleKind::Room, room_id, false).await?;
                self.delete_rules(
                    current_custom_rules,
                    vec![(RuleKind::Room, room_id.to_string())],
                )
                .await?;
            }
            // from `Mute` to `Mute`
            (Some(RoomNotificationMode::Mute), RoomNotificationMode::Mute) => {}
            // from anything > Mute
            (_, RoomNotificationMode::Mute) => {
                // Insert the rule before deleting the other custom rules to obtain the correct
                // mode in the next sync response.
                let current_custom_rules = self.get_custom_rules_for_room(room_id).await;
                self.insert_room_rule(RuleKind::Override, room_id, false).await?;
                self.delete_rules(current_custom_rules, vec![]).await?;
            }
            // from `AllMessages` to `AllMessages`
            (Some(RoomNotificationMode::AllMessages), RoomNotificationMode::AllMessages) => {}
            // from `MentionsAndKeywordsOnly` to `MentionsAndKeywordsOnly`
            (
                Some(RoomNotificationMode::MentionsAndKeywordsOnly),
                RoomNotificationMode::MentionsAndKeywordsOnly,
            ) => {}
        }

        Ok(())
    }

    /// Deletes a list of rules.
    ///
    /// # Arguments
    ///
    /// * `rules` - A `Vec<(RuleKind, String)>` representing the kind and rule
    ///   ID of each rules
    /// * `exceptions` - A `Vec<(RuleKind, String)>` containing rules to not
    ///   delete
    async fn delete_rules(
        &self,
        rules: Vec<(RuleKind, String)>,
        exceptions: Vec<(RuleKind, String)>,
    ) -> Result<(), NotificationSettingsError> {
        let mut ruleset = self.ruleset.write().await;

        let mut rules_ = Rules::new(ruleset.clone());
        let commands = rules_
            .delete_rules(rules, exceptions)
            .map_err(|_| NotificationSettingsError::UnableToRemovePushRule)?;

        self.execute_commands(commands)
            .await
            .map_err(|_| NotificationSettingsError::UnableToRemovePushRule)?;
        *ruleset = rules_.ruleset;

        Ok(())
    }

    /// Delete all user defined rules for a room.
    ///
    /// # Arguments
    ///
    /// * `room_id` - A `RoomId`
    pub async fn delete_user_defined_room_rules(
        &self,
        room_id: &RoomId,
    ) -> Result<(), NotificationSettingsError> {
        let rules = self.get_custom_rules_for_room(room_id).await;
        self.delete_rules(rules, vec![]).await
    }

    /// Insert a new push rule for a given `RoomId`.
    ///
    /// # Arguments
    ///
    /// * `kind` - A `RuleKind`
    /// * `room_id` - A `RoomId`
    /// * `notify` - `true` if this rule should have a `Notify` action, `false`
    ///   otherwise
    async fn insert_room_rule(
        &self,
        kind: RuleKind,
        room_id: &RoomId,
        notify: bool,
    ) -> Result<(), NotificationSettingsError> {
        let ruleset = &mut *self.ruleset.write().await;
        let mut rules = Rules::new(ruleset.clone());
        let commands = rules
            .insert_room_rule(kind, room_id, notify)
            .map_err(|_| NotificationSettingsError::UnableToAddPushRule)?;
        self.execute_commands(commands)
            .await
            .map_err(|_| NotificationSettingsError::UnableToAddPushRule)?;
        *ruleset = rules.ruleset;

        Ok(())
    }

    /// Unmute a `Room`.
    ///
    /// # Arguments
    ///
    /// * `room_id` - A `RoomId`
    pub async fn unmute_room(&self, room_id: &RoomId) -> Result<(), NotificationSettingsError> {
        // Get the current mode
        let room_mode = self.get_user_defined_room_notification_mode(room_id).await;

        if let Some(room_mode) = room_mode {
            if room_mode != RoomNotificationMode::Mute {
                // Already unmuted
                return Ok(());
            }
        } else {
            // This is the default mode, create a custom rule to unmute this room by setting
            // the mode to `AllMessages`
            return self
                .set_room_notification_mode(room_id, RoomNotificationMode::AllMessages)
                .await;
        }

        // Get default mode for this room
        let room = self.client.get_room(room_id);
        if room.is_none() {
            return Err(NotificationSettingsError::RoomNotFound);
        }
        let room = room.unwrap();
        let is_encrypted = room.is_encrypted().await.unwrap_or(false);
        let members_count = room.joined_members_count();

        let default_mode =
            self.get_default_room_notification_mode(is_encrypted, members_count).await;

        // If the default mode is `Mute`, set it to `AllMessages`
        if default_mode == RoomNotificationMode::Mute {
            self.set_room_notification_mode(room_id, RoomNotificationMode::AllMessages).await
        } else {
            // Otherwise, delete user defined rules to use the default mode
            self.delete_user_defined_room_rules(room_id).await
        }
    }

    /// Execute a list of commands
    ///
    /// # Arguments
    ///
    /// * `commands` - A `Vec<Command>` to execute
    async fn execute_commands(&self, commands: Vec<Command>) -> Result<()> {
        for command in &commands {
            self.execute(command.clone()).await?;
        }
        Ok(())
    }

    /// Execute a command
    ///
    /// # Arguments
    ///
    /// * `command` - A `Command` to execute
    async fn execute(&self, command: Command) -> Result<()> {
        match command {
            Command::DeletePushRule(scope, kind, rule_id) => {
                let request = delete_pushrule::v3::Request::new(scope, kind, rule_id);
                self.client.send(request, None).await?;
            }
            Command::SetPushRule(scope, rule) => {
                let request = set_pushrule::v3::Request::new(scope, rule);
                self.client.send(request, None).await?;
            }
            Command::SetPushRuleEnabled(scope, kind, rule_id, enabled) => {
                let request = set_pushrule_enabled::v3::Request::new(scope, kind, rule_id, enabled);
                self.client.send(request, None).await?;
            }
        }
        Ok(())
    }
}

// The http mocking library is not supported for wasm32
#[cfg(all(test, not(target_arch = "wasm32")))]
pub(crate) mod tests {

    use matrix_sdk_test::async_test;
    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    use ruma::{
        push::{
            Action, NewPatternedPushRule, NewPushRule, PredefinedOverrideRuleId,
            PredefinedUnderrideRuleId, RuleKind,
        },
        RoomId,
    };
    use wiremock::{matchers::method, Mock, MockServer, ResponseTemplate};

    use crate::{notification_settings::RoomNotificationMode, test_utils::logged_in_client};

    #[async_test]
    async fn get_default_room_notification_mode_encrypted_one_to_one() {
        let server = MockServer::start().await;
        let client = logged_in_client(Some(server.uri())).await;

        let notification_settings = client.notification_settings().await;
        let mut ruleset = notification_settings.ruleset.read().await.clone();

        let encrypted: bool = true;
        let members_count = 2;

        let mode = notification_settings
            .get_default_room_notification_mode(encrypted, members_count)
            .await;
        assert_eq!(mode, RoomNotificationMode::AllMessages);

        let result = ruleset.set_enabled(
            RuleKind::Underride,
            PredefinedUnderrideRuleId::EncryptedRoomOneToOne,
            false,
        );
        assert!(result.is_ok());

        let result =
            ruleset.set_enabled(RuleKind::Override, PredefinedOverrideRuleId::IsUserMention, true);
        assert!(result.is_ok());
        notification_settings.set_ruleset(&ruleset).await;

        let result = ruleset.set_actions(
            RuleKind::Override,
            PredefinedOverrideRuleId::IsUserMention,
            vec![Action::Notify],
        );
        assert!(result.is_ok());

        let mode = notification_settings
            .get_default_room_notification_mode(encrypted, members_count)
            .await;
        assert_eq!(mode, RoomNotificationMode::MentionsAndKeywordsOnly)
    }

    #[async_test]
    async fn get_default_room_notification_mode_one_to_one() {
        let server = MockServer::start().await;
        let client = logged_in_client(Some(server.uri())).await;

        let notification_settings = client.notification_settings().await;
        let mut ruleset = notification_settings.ruleset.read().await.clone();

        let encrypted = false;
        let members_count = 2;

        let mode = notification_settings
            .get_default_room_notification_mode(encrypted, members_count)
            .await;
        assert_eq!(mode, RoomNotificationMode::AllMessages);

        let result = ruleset.set_enabled(
            RuleKind::Underride,
            PredefinedUnderrideRuleId::RoomOneToOne,
            false,
        );
        assert!(result.is_ok());

        let result =
            ruleset.set_enabled(RuleKind::Override, PredefinedOverrideRuleId::IsUserMention, true);
        assert!(result.is_ok());

        let result =
            ruleset.set_enabled(RuleKind::Override, PredefinedOverrideRuleId::IsUserMention, true);
        assert!(result.is_ok());
        notification_settings.set_ruleset(&ruleset).await;

        let mode = notification_settings
            .get_default_room_notification_mode(encrypted, members_count)
            .await;
        assert_eq!(mode, RoomNotificationMode::MentionsAndKeywordsOnly);
    }

    #[async_test]
    async fn get_default_room_notification_mode_encrypted_room() {
        let server = MockServer::start().await;
        let client = logged_in_client(Some(server.uri())).await;
        Mock::given(method("PUT")).respond_with(ResponseTemplate::new(200)).mount(&server).await;
        Mock::given(method("DELETE")).respond_with(ResponseTemplate::new(200)).mount(&server).await;

        let notification_settings = client.notification_settings().await;
        let mut ruleset = notification_settings.ruleset.read().await.clone();

        let encrypted: bool = true;
        let members_count = 3;

        let mode = notification_settings
            .get_default_room_notification_mode(encrypted, members_count)
            .await;
        assert_eq!(mode, RoomNotificationMode::AllMessages);

        let result =
            ruleset.set_enabled(RuleKind::Underride, PredefinedUnderrideRuleId::Encrypted, false);
        assert!(result.is_ok());

        let result =
            ruleset.set_enabled(RuleKind::Override, PredefinedOverrideRuleId::IsUserMention, true);
        assert!(result.is_ok());

        let result = ruleset.set_actions(
            RuleKind::Override,
            PredefinedOverrideRuleId::IsUserMention,
            vec![Action::Notify],
        );
        assert!(result.is_ok());

        notification_settings.set_ruleset(&ruleset).await;

        let mode = notification_settings
            .get_default_room_notification_mode(encrypted, members_count)
            .await;
        assert_eq!(mode, RoomNotificationMode::MentionsAndKeywordsOnly);
    }

    #[async_test]
    async fn get_default_room_notification_mode_unencrypted_room() {
        let server = MockServer::start().await;
        let client = logged_in_client(Some(server.uri())).await;

        let notification_settings = client.notification_settings().await;
        let mut ruleset = notification_settings.ruleset.read().await.clone();

        let encrypted: bool = false;
        let members_count = 3;

        let mode = notification_settings
            .get_default_room_notification_mode(encrypted, members_count)
            .await;
        assert_eq!(mode, RoomNotificationMode::AllMessages);

        let result =
            ruleset.set_enabled(RuleKind::Underride, PredefinedUnderrideRuleId::Message, false);
        assert!(result.is_ok());

        let result =
            ruleset.set_enabled(RuleKind::Override, PredefinedOverrideRuleId::IsUserMention, true);
        assert!(result.is_ok());

        let result = ruleset.set_actions(
            RuleKind::Override,
            PredefinedOverrideRuleId::IsUserMention,
            vec![Action::Notify],
        );
        assert!(result.is_ok());

        notification_settings.set_ruleset(&ruleset).await;

        let mode = notification_settings
            .get_default_room_notification_mode(encrypted, members_count)
            .await;
        assert_eq!(mode, RoomNotificationMode::MentionsAndKeywordsOnly);
    }

    #[async_test]
    async fn delete_user_defined_room_rules() {
        let server = MockServer::start().await;
        let client = logged_in_client(Some(server.uri())).await;
        Mock::given(method("PUT")).respond_with(ResponseTemplate::new(200)).mount(&server).await;
        Mock::given(method("DELETE")).respond_with(ResponseTemplate::new(200)).mount(&server).await;

        let notification_settings = client.notification_settings().await;
        let room_id = RoomId::parse("!test_room:matrix.org").unwrap();

        let mode = notification_settings.get_user_defined_room_notification_mode(&room_id).await;
        assert!(mode.is_none());

        // Add a Room rule
        let result = notification_settings.insert_room_rule(RuleKind::Room, &room_id, false).await;
        assert!(result.is_ok());

        // Add a an Override rule
        let result =
            notification_settings.insert_room_rule(RuleKind::Override, &room_id, false).await;
        assert!(result.is_ok());

        let custom_rules = notification_settings.get_custom_rules_for_room(&room_id).await;
        assert_eq!(custom_rules.len(), 2);

        // Delete the custom rules
        let result = notification_settings.delete_user_defined_room_rules(&room_id).await;
        assert!(result.is_ok());

        let custom_rules = notification_settings.get_custom_rules_for_room(&room_id).await;
        assert!(custom_rules.is_empty());
    }

    #[async_test]
    async fn set_room_notification_mode_default_to_all_messages() {
        let server = MockServer::start().await;
        let client = logged_in_client(Some(server.uri())).await;

        Mock::given(method("PUT")).respond_with(ResponseTemplate::new(200)).mount(&server).await;
        Mock::given(method("DELETE")).respond_with(ResponseTemplate::new(200)).mount(&server).await;

        let notification_settings = client.notification_settings().await;
        let room_id = RoomId::parse("!test_room:matrix.org").unwrap();

        // Default -> All
        let mode = notification_settings.get_user_defined_room_notification_mode(&room_id).await;
        assert!(mode.is_none());

        let result = notification_settings
            .set_room_notification_mode(&room_id, RoomNotificationMode::AllMessages)
            .await;
        assert!(result.is_ok());

        let new_mode = notification_settings
            .get_user_defined_room_notification_mode(&room_id)
            .await
            .expect("A mode is expected.");
        assert_eq!(new_mode, RoomNotificationMode::AllMessages);
    }

    #[async_test]
    async fn set_room_notification_mode_mentions_keywords_to_all_messages() {
        let server = MockServer::start().await;
        let client = logged_in_client(Some(server.uri())).await;

        Mock::given(method("PUT")).respond_with(ResponseTemplate::new(200)).mount(&server).await;
        Mock::given(method("DELETE")).respond_with(ResponseTemplate::new(200)).mount(&server).await;

        let notification_settings = client.notification_settings().await;
        let room_id = RoomId::parse("!test_room:matrix.org").unwrap();

        let result = notification_settings.insert_room_rule(RuleKind::Room, &room_id, false).await;
        assert!(result.is_ok());

        let mode = notification_settings.get_user_defined_room_notification_mode(&room_id).await;
        assert_eq!(mode, Some(RoomNotificationMode::MentionsAndKeywordsOnly));

        // M&K -> All
        let result = notification_settings
            .set_room_notification_mode(&room_id, RoomNotificationMode::AllMessages)
            .await;
        assert!(result.is_ok());

        let new_mode = notification_settings
            .get_user_defined_room_notification_mode(&room_id)
            .await
            .expect("A mode is expected");
        assert_eq!(new_mode, RoomNotificationMode::AllMessages);
    }

    #[async_test]
    async fn set_room_notification_mode_mute_to_all_messages() {
        let server = MockServer::start().await;
        let client = logged_in_client(Some(server.uri())).await;

        Mock::given(method("PUT")).respond_with(ResponseTemplate::new(200)).mount(&server).await;
        Mock::given(method("DELETE")).respond_with(ResponseTemplate::new(200)).mount(&server).await;

        let notification_settings = client.notification_settings().await;
        let room_id = RoomId::parse("!test_room:matrix.org").unwrap();

        let result =
            notification_settings.insert_room_rule(RuleKind::Override, &room_id, false).await;
        assert!(result.is_ok());

        let mode = notification_settings.get_user_defined_room_notification_mode(&room_id).await;
        assert_eq!(mode, Some(RoomNotificationMode::Mute));

        // Mute -> All
        let result = notification_settings
            .set_room_notification_mode(&room_id, RoomNotificationMode::AllMessages)
            .await;
        assert!(result.is_ok());

        let new_mode = notification_settings
            .get_user_defined_room_notification_mode(&room_id)
            .await
            .expect("A mode is expected");
        assert_eq!(new_mode, RoomNotificationMode::AllMessages);
    }

    #[async_test]
    async fn set_room_notification_mode_default_to_mentions_keywords() {
        let server = MockServer::start().await;
        let client = logged_in_client(Some(server.uri())).await;

        Mock::given(method("PUT")).respond_with(ResponseTemplate::new(200)).mount(&server).await;
        Mock::given(method("DELETE")).respond_with(ResponseTemplate::new(200)).mount(&server).await;

        let notification_settings = client.notification_settings().await;
        let room_id = RoomId::parse("!test_room:matrix.org").unwrap();

        let mode = notification_settings.get_user_defined_room_notification_mode(&room_id).await;
        assert!(mode.is_none());

        // Default -> M&K
        let result = notification_settings
            .set_room_notification_mode(&room_id, RoomNotificationMode::MentionsAndKeywordsOnly)
            .await;
        assert!(result.is_ok());

        let new_mode = notification_settings
            .get_user_defined_room_notification_mode(&room_id)
            .await
            .expect("A mode is expected");
        assert_eq!(new_mode, RoomNotificationMode::MentionsAndKeywordsOnly);
    }

    #[async_test]
    async fn set_room_notification_mode_all_messages_to_mentions_keywords() {
        let server = MockServer::start().await;
        let client = logged_in_client(Some(server.uri())).await;

        Mock::given(method("PUT")).respond_with(ResponseTemplate::new(200)).mount(&server).await;
        Mock::given(method("DELETE")).respond_with(ResponseTemplate::new(200)).mount(&server).await;

        let notification_settings = client.notification_settings().await;
        let room_id = RoomId::parse("!test_room:matrix.org").unwrap();

        let result = notification_settings.insert_room_rule(RuleKind::Room, &room_id, true).await;
        assert!(result.is_ok());

        let mode = notification_settings.get_user_defined_room_notification_mode(&room_id).await;
        assert_eq!(mode, Some(RoomNotificationMode::AllMessages));

        // AllMessage -> M&K
        let result = notification_settings
            .set_room_notification_mode(&room_id, RoomNotificationMode::MentionsAndKeywordsOnly)
            .await;
        assert!(result.is_ok());

        let new_mode = notification_settings
            .get_user_defined_room_notification_mode(&room_id)
            .await
            .expect("A mode is expected");
        assert_eq!(new_mode, RoomNotificationMode::MentionsAndKeywordsOnly);
    }

    #[async_test]
    async fn set_room_notification_mode_mute_to_mentions_keywords() {
        let server = MockServer::start().await;
        let client = logged_in_client(Some(server.uri())).await;

        Mock::given(method("PUT")).respond_with(ResponseTemplate::new(200)).mount(&server).await;
        Mock::given(method("DELETE")).respond_with(ResponseTemplate::new(200)).mount(&server).await;

        let notification_settings = client.notification_settings().await;
        let room_id = RoomId::parse("!test_room:matrix.org").unwrap();

        let result =
            notification_settings.insert_room_rule(RuleKind::Override, &room_id, false).await;
        assert!(result.is_ok());

        let mode = notification_settings.get_user_defined_room_notification_mode(&room_id).await;
        assert_eq!(mode, Some(RoomNotificationMode::Mute));

        // Mute -> M&K
        let result = notification_settings
            .set_room_notification_mode(&room_id, RoomNotificationMode::MentionsAndKeywordsOnly)
            .await;
        assert!(result.is_ok());

        let new_mode = notification_settings
            .get_user_defined_room_notification_mode(&room_id)
            .await
            .expect("A mode is expected");
        assert_eq!(new_mode, RoomNotificationMode::MentionsAndKeywordsOnly);
    }

    #[async_test]
    async fn set_room_notification_default_to_mute() {
        let server = MockServer::start().await;
        let client = logged_in_client(Some(server.uri())).await;

        Mock::given(method("PUT")).respond_with(ResponseTemplate::new(200)).mount(&server).await;
        Mock::given(method("DELETE")).respond_with(ResponseTemplate::new(200)).mount(&server).await;

        let notification_settings = client.notification_settings().await;
        let room_id = RoomId::parse("!test_room:matrix.org").unwrap();

        let mode = notification_settings.get_user_defined_room_notification_mode(&room_id).await;
        assert!(mode.is_none());

        // Default -> Mute
        let result = notification_settings
            .set_room_notification_mode(&room_id, RoomNotificationMode::Mute)
            .await;
        assert!(result.is_ok());

        let new_mode = notification_settings
            .get_user_defined_room_notification_mode(&room_id)
            .await
            .expect("A mode is expected");
        assert_eq!(new_mode, RoomNotificationMode::Mute);
    }

    #[async_test]
    async fn set_room_notification_all_messages_to_mute() {
        let server = MockServer::start().await;
        let client = logged_in_client(Some(server.uri())).await;

        Mock::given(method("PUT")).respond_with(ResponseTemplate::new(200)).mount(&server).await;
        Mock::given(method("DELETE")).respond_with(ResponseTemplate::new(200)).mount(&server).await;

        let notification_settings = client.notification_settings().await;
        let room_id = RoomId::parse("!test_room:matrix.org").unwrap();

        let result = notification_settings.insert_room_rule(RuleKind::Room, &room_id, true).await;
        assert!(result.is_ok());

        let mode = notification_settings.get_user_defined_room_notification_mode(&room_id).await;
        assert_eq!(mode, Some(RoomNotificationMode::AllMessages));

        // AllMessages -> Mute
        let result = notification_settings
            .set_room_notification_mode(&room_id, RoomNotificationMode::Mute)
            .await;
        assert!(result.is_ok());

        let new_mode = notification_settings
            .get_user_defined_room_notification_mode(&room_id)
            .await
            .expect("A mode is expected");
        assert_eq!(new_mode, RoomNotificationMode::Mute);
    }

    #[async_test]
    async fn set_room_notification_mentions_keywords_to_mute() {
        let server = MockServer::start().await;
        let client = logged_in_client(Some(server.uri())).await;

        Mock::given(method("PUT")).respond_with(ResponseTemplate::new(200)).mount(&server).await;
        Mock::given(method("DELETE")).respond_with(ResponseTemplate::new(200)).mount(&server).await;

        let notification_settings = client.notification_settings().await;
        let room_id = RoomId::parse("!test_room:matrix.org").unwrap();

        let result = notification_settings.insert_room_rule(RuleKind::Room, &room_id, false).await;
        assert!(result.is_ok());

        let mode = notification_settings.get_user_defined_room_notification_mode(&room_id).await;
        assert_eq!(mode, Some(RoomNotificationMode::MentionsAndKeywordsOnly));

        // M&K -> Mute
        let result = notification_settings
            .set_room_notification_mode(&room_id, RoomNotificationMode::Mute)
            .await;
        assert!(result.is_ok());

        let new_mode = notification_settings
            .get_user_defined_room_notification_mode(&room_id)
            .await
            .expect("A mode is expected");
        assert_eq!(new_mode, RoomNotificationMode::Mute);
    }

    #[async_test]
    async fn contains_keyword_rules() {
        let server = MockServer::start().await;
        let client = logged_in_client(Some(server.uri())).await;

        let notification_settings = client.notification_settings().await;
        let mut ruleset = notification_settings.ruleset.read().await.clone();

        let contains_keywords_rules = notification_settings.contains_keyword_rules().await;
        assert!(!contains_keywords_rules);

        let rule =
            NewPatternedPushRule::new("keyword".into(), "keyword".into(), vec![Action::Notify]);

        _ = ruleset.insert(NewPushRule::Content(rule), None, None);
        notification_settings.set_ruleset(&ruleset).await;

        let contains_keywords_rules = notification_settings.contains_keyword_rules().await;
        assert!(contains_keywords_rules);
    }

    // #[async_test]
    // async fn is_user_mention_enabled() {
    //     let server = MockServer::start().await;
    //     let client = logged_in_client(Some(server.uri())).await;

    //     let mut ruleset = client.account().push_rules().await.unwrap();
    //     let notification_settings = client.notification_settings();

    //     let result =
    //         ruleset.set_enabled(RuleKind::Override,
    // PredefinedOverrideRuleId::IsUserMention, true);     assert!(result.
    // is_ok());     assert!(notification_settings.
    // is_user_mention_enabled()); }

    // #[async_test]
    // async fn is_room_mention_enabled() {
    //     let server = MockServer::start().await;
    //     let client = logged_in_client(Some(server.uri())).await;

    //     let mut ruleset: Ruleset =
    // client.account().push_rules().await.unwrap();
    //     let notification_settings = client.notification_settings();

    //     let result =
    //         ruleset.set_enabled(RuleKind::Override,
    // PredefinedOverrideRuleId::IsRoomMention, true);     assert!(result.
    // is_ok());     assert!(notification_settings.is_room_mention_enabled(&
    // ruleset)); }
}
