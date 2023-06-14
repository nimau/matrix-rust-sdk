use ruma::{
    api::client::push::RuleScope,
    push::{
        Action, InsertPushRuleError, NewConditionalPushRule, NewPushRule, NewSimplePushRule,
        PredefinedContentRuleId, PredefinedOverrideRuleId, PredefinedUnderrideRuleId,
        PushCondition, RemovePushRuleError, RuleKind, Ruleset, Tweak,
    },
    RoomId,
};

use super::RoomNotificationMode;
use crate::NotificationSettingsError;

#[derive(Clone)]
pub(crate) enum Command {
    SetPushRule(RuleScope, NewPushRule),
    SetPushRuleEnabled(RuleScope, RuleKind, String, bool),
    DeletePushRule(RuleScope, RuleKind, String),
}

pub(crate) struct RulesetProxy {
    pub ruleset: Ruleset,
}

impl RulesetProxy {
    pub(crate) fn new(ruleset: Ruleset) -> Self {
        RulesetProxy { ruleset }
    }

    /// Gets all user defined rules matching a given `room_id`.
    ///
    /// # Arguments
    ///
    /// * `room_id` - A `RoomId`
    pub(crate) fn get_custom_rules_for_room(&self, room_id: &RoomId) -> Vec<(RuleKind, String)> {
        let mut custom_rules: Vec<(RuleKind, String)> = Vec::new();

        // add any `Override` rules matching this `room_id`
        for rule in &self.ruleset.override_ {
            // if the rule_id is the room_id
            if rule.rule_id == *room_id {
                custom_rules.push((RuleKind::Override, rule.rule_id.clone()));
                continue;
            }
            // if the rule contains a condition matching this `room_id`
            if rule.conditions.iter().any(|x| matches!(
                x,
                PushCondition::EventMatch { key, pattern } if key == "room_id" && *pattern == *room_id
            )) {
                custom_rules.push((RuleKind::Override, rule.rule_id.clone()));
                continue;
            }
        }

        // add any `Room` rules matching this `room_id`
        if let Some(rule) = self.ruleset.room.iter().find(|x| x.rule_id == *room_id).cloned() {
            custom_rules.push((RuleKind::Room, rule.rule_id.to_string()));
        }

        // add any `Underride` rules matching this `room_id`
        for rule in &self.ruleset.underride {
            // if the rule_id is the room_id
            if rule.rule_id == *room_id {
                custom_rules.push((RuleKind::Underride, rule.rule_id.clone()));
                continue;
            }
            // if the rule contains a condition matching this `room_id`
            if rule.conditions.iter().any(|x| matches!(
                x,
                PushCondition::EventMatch { key, pattern } if key == "room_id" && *pattern == *room_id
            )) {
                custom_rules.push((RuleKind::Underride, rule.rule_id.clone()));
                continue;
            }
        }

        custom_rules
    }

    /// Gets the user defined notification mode for a room.
    ///
    /// # Arguments
    ///
    /// * `room_id` - A `RoomId`
    pub(crate) fn get_user_defined_room_notification_mode(
        &self,
        room_id: &RoomId,
    ) -> Option<RoomNotificationMode> {
        // Search for an enabled `Override` rule
        if let Some(rule) = self.ruleset.override_.iter().find(|x| x.enabled) {
            // without a Notify action
            if !rule.actions.iter().any(|x| matches!(x, Action::Notify)) {
                // with a condition of type `EventMatch` for this `room_id`
                if rule.conditions.iter().any(|x| matches!(
                    x,
                    PushCondition::EventMatch { key, pattern } if key == "room_id" && *pattern == *room_id
                )) {
                    return Some(RoomNotificationMode::Mute);
                }
            }
        }

        // Search for an enabled `Room` rule where `rule_id` is the `room_id`
        if let Some(rule) = self.ruleset.room.iter().find(|x| x.enabled && x.rule_id == *room_id) {
            // if this rule contains a `Notify` action
            if rule.actions.iter().any(|x| matches!(x, Action::Notify)) {
                return Some(RoomNotificationMode::AllMessages);
            } else {
                return Some(RoomNotificationMode::MentionsAndKeywordsOnly);
            }
        }

        // There is no custom rule matching this `room_id`
        None
    }

    /// Gets the `PredefinedUnderrideRuleId` corresponding to the given
    /// criteria.
    ///
    /// # Arguments
    ///
    /// * `is_encrypted` - `true` if the room is encrypted
    /// * `members_count` - the room members count
    fn get_predefined_underride_room_rule_id(
        &self,
        is_encrypted: bool,
        members_count: u64,
    ) -> PredefinedUnderrideRuleId {
        match (is_encrypted, members_count) {
            (true, 2) => PredefinedUnderrideRuleId::EncryptedRoomOneToOne,
            (false, 2) => PredefinedUnderrideRuleId::RoomOneToOne,
            (true, _) => PredefinedUnderrideRuleId::Encrypted,
            (false, _) => PredefinedUnderrideRuleId::Message,
        }
    }

    /// Gets the default notification mode for a room.
    ///
    /// # Arguments
    ///
    /// * `is_encrypted` - `true` if the room is encrypted
    /// * `members_count` - the room members count
    pub(crate) fn get_default_room_notification_mode(
        &self,
        is_encrypted: bool,
        members_count: u64,
    ) -> RoomNotificationMode {
        // get the correct default rule ID based on `is_encrypted` and `members_count`
        let rule_id = self.get_predefined_underride_room_rule_id(is_encrypted, members_count);

        // If there is an `Underride` rule that should trigger a notification, the mode
        // is `AllMessages`
        if self.ruleset.underride.iter().any(|r| {
            r.enabled
                && r.rule_id == rule_id.to_string()
                && r.actions.iter().any(|a| a.should_notify())
        }) {
            RoomNotificationMode::AllMessages
        } else {
            // Otherwise, the mode is `MentionsAndKeywordsOnly`
            RoomNotificationMode::MentionsAndKeywordsOnly
        }
    }

    /// Get whether the `IsUserMention` rule is enabled.
    pub(crate) fn is_user_mention_enabled(&self) -> bool {
        // Search for an enabled `Override` rule `IsUserMention` (MSC3952).
        // This is a new push rule that may not yet be present.
        if let Some(rule) =
            self.ruleset.get(RuleKind::Override, PredefinedOverrideRuleId::IsUserMention)
        {
            if rule.enabled() {
                return true;
            }
        }

        // Fallback to deprecated rules for compatibility.
        #[allow(deprecated)]
        let mentions_and_keywords_rules_id = vec![
            PredefinedOverrideRuleId::ContainsDisplayName.to_string(),
            PredefinedContentRuleId::ContainsUserName.to_string(),
        ];
        self.ruleset.content.iter().any(|r| {
            r.enabled
                && mentions_and_keywords_rules_id.contains(&r.rule_id)
                && r.actions.iter().any(|a| a.should_notify())
        })
    }

    /// Get whether the `IsRoomMention` rule is enabled.
    pub(crate) fn is_room_mention_enabled(&self) -> bool {
        // Search for an enabled `Override` rule `IsRoomMention` (MSC3952).
        // This is a new push rule that may not yet be present.
        if let Some(rule) =
            self.ruleset.get(RuleKind::Override, PredefinedOverrideRuleId::IsRoomMention)
        {
            if rule.enabled() {
                return true;
            }
        }

        // Fallback to deprecated rule for compatibility
        #[allow(deprecated)]
        self.ruleset.override_.iter().any(|r| {
            r.enabled
                && r.rule_id == PredefinedOverrideRuleId::RoomNotif.to_string()
                && r.actions.iter().any(|a| a.should_notify())
        })
    }

    /// Get whether the given ruleset contains some enabled keywords rules.
    pub(crate) fn contains_keyword_rules(&self) -> bool {
        // Search for a user defined `Content` rule.
        self.ruleset.content.iter().any(|r| !r.default && r.enabled)
    }

    /// Get whether a rule is enabled.
    ///
    /// # Arguments
    ///
    /// * `kind` - A `RuleKind`
    /// * `rule_id` - A `PredefinedUnderrideRuleId`
    pub(crate) fn is_rule_enabled(
        &self,
        kind: RuleKind,
        rule_id: String,
    ) -> Result<bool, NotificationSettingsError> {
        if rule_id == PredefinedOverrideRuleId::IsRoomMention.to_string() {
            Ok(self.is_room_mention_enabled())
        } else if rule_id == PredefinedOverrideRuleId::IsUserMention.to_string() {
            Ok(self.is_user_mention_enabled())
        } else if let Some(rule) = self.ruleset.get(kind, rule_id) {
            Ok(rule.enabled())
        } else {
            Err(NotificationSettingsError::RuleNotFound)
        }
    }

    /// Insert a new `Room` push rule for a given `room_id`.
    ///
    /// # Arguments
    ///
    /// * `kind` - A `RuleKind`
    /// * `room_id` - A room ID
    /// * `notify` - `true` if this rule should have a `Notify` action, `false`
    ///   otherwise
    pub(crate) fn insert_room_rule(
        &mut self,
        kind: RuleKind,
        room_id: &RoomId,
        notify: bool,
    ) -> Result<Vec<Command>, InsertPushRuleError> {
        let mut commands: Vec<Command> = vec![];
        let actions = if notify {
            vec![Action::Notify, Action::SetTweak(Tweak::Sound("default".into()))]
        } else {
            vec![]
        };

        match kind {
            RuleKind::Override => {
                // Insert a new push rule matching this `room_id`
                let new_rule = NewConditionalPushRule::new(
                    room_id.to_string(),
                    vec![PushCondition::EventMatch {
                        key: "room_id".into(),
                        pattern: room_id.to_string(),
                    }],
                    actions,
                );
                let new_rule = NewPushRule::Override(new_rule);
                self.ruleset.insert(new_rule.clone(), None, None)?;
                commands.push(Command::SetPushRule(RuleScope::Global, new_rule));
            }
            RuleKind::Room => {
                // Insert a new `Room` push rule for this `room_id`
                let new_rule = NewSimplePushRule::new(room_id.to_owned(), actions);
                let new_rule = NewPushRule::Room(new_rule);
                self.ruleset.insert(new_rule.clone(), None, None)?;
                commands.push(Command::SetPushRule(RuleScope::Global, new_rule));
            }
            _ => {}
        }

        Ok(commands)
    }

    /// Deletes a list of rules.
    ///
    /// # Arguments
    ///
    /// * `rules` - A `Vec<(RuleKind, String)>` representing the kind and rule
    ///   ID of each rules
    /// * `exceptions` - A `Vec<(RuleKind, String)>` containing rules to not
    ///   delete
    pub(crate) fn delete_rules(
        &mut self,
        rules: Vec<(RuleKind, String)>,
        exceptions: Vec<(RuleKind, String)>,
    ) -> Result<Vec<Command>, RemovePushRuleError> {
        let mut commands: Vec<Command> = vec![];
        for (rule_kind, rule_id) in &rules {
            if exceptions.contains(&(rule_kind.clone(), rule_id.clone())) {
                continue;
            }
            self.ruleset.remove(rule_kind.clone(), rule_id.clone())?;
            commands.push(Command::DeletePushRule(
                RuleScope::Global,
                rule_kind.clone(),
                rule_id.clone(),
            ))
        }
        Ok(commands)
    }

    /// Sets whether a push rule is enabled.
    ///
    /// # Arguments
    ///
    /// * `scope` - A `RuleScope`
    /// * `kind` - A `RuleKind`
    /// * `rule_id` - A rule ID
    /// * `enabled` - A `bool` indicating whether the rule should be activated
    pub(crate) fn set_pushrule_enabled(
        &mut self,
        scope: RuleScope,
        kind: RuleKind,
        rule_id: String,
        enabled: bool,
    ) -> Result<Vec<Command>, NotificationSettingsError> {
        if rule_id == PredefinedOverrideRuleId::IsRoomMention.to_string() {
            // Handle specific case for `PredefinedOverrideRuleId::IsRoomMention`
            self.set_room_mention_enabled(enabled)
        } else if rule_id == PredefinedOverrideRuleId::IsUserMention.to_string() {
            // Handle specific case for `PredefinedOverrideRuleId::IsUserMention`
            self.set_user_mention_enabled(enabled)
        } else {
            let mut commands: Vec<Command> = vec![];
            self.ruleset.set_enabled(kind.clone(), rule_id.clone(), enabled)?;
            commands.push(Command::SetPushRuleEnabled(scope, kind, rule_id, enabled));
            Ok(commands)
        }
    }

    /// Set whether the `IsUserMention` rule is enabled.
    ///
    /// # Arguments
    ///
    /// * `enabled` - `true` to enable the `IsUserMention` rule, `false`
    ///   otherwise
    fn set_user_mention_enabled(
        &mut self,
        enabled: bool,
    ) -> Result<Vec<Command>, NotificationSettingsError> {
        let mut commands: Vec<Command> = vec![];

        // Sets the `IsUserMention` `Override` rule (MSC3952).
        // This is a new push rule that may not yet be present.
        let result_commands = &mut self.set_pushrule_enabled(
            RuleScope::Global,
            RuleKind::Override,
            PredefinedOverrideRuleId::IsUserMention.to_string(),
            enabled,
        )?;
        commands.append(result_commands);

        // For compatibility purpose, we still need to set `ContainsUserName` and
        // `ContainsDisplayName` (deprecated rules).
        #[allow(deprecated)]
        {
            // `ContainsUserName`
            let result_commands = &mut self.set_pushrule_enabled(
                RuleScope::Global,
                RuleKind::Content,
                PredefinedContentRuleId::ContainsUserName.to_string(),
                enabled,
            )?;
            commands.append(result_commands);

            // `ContainsDisplayName`
            let result_commands = &mut self.set_pushrule_enabled(
                RuleScope::Global,
                RuleKind::Override,
                PredefinedOverrideRuleId::ContainsDisplayName.to_string(),
                enabled,
            )?;
            commands.append(result_commands);
        }

        Ok(commands)
    }

    /// Set whether the `IsRoomMention` rule is enabled.
    ///
    /// # Arguments
    ///
    /// * `enabled` - `true` to enable the `IsRoomMention` rule, `false`
    ///   otherwise
    fn set_room_mention_enabled(
        &mut self,
        enabled: bool,
    ) -> Result<Vec<Command>, NotificationSettingsError> {
        let mut commands: Vec<Command> = vec![];

        // Sets the `IsRoomMention` `Override` rule (MSC3952).
        // This is a new push rule that may not yet be present.
        let result_commands = &mut self.set_pushrule_enabled(
            RuleScope::Global,
            RuleKind::Override,
            PredefinedOverrideRuleId::IsRoomMention.to_string(),
            enabled,
        )?;
        commands.append(result_commands);

        // For compatibility purpose, we still need to set `RoomNotif` (deprecated
        // rule).
        #[allow(deprecated)]
        {
            let result_commands = &mut self.set_pushrule_enabled(
                RuleScope::Global,
                RuleKind::Override,
                PredefinedOverrideRuleId::RoomNotif.to_string(),
                enabled,
            )?;
            commands.append(result_commands);
        }

        Ok(commands)
    }
}

#[cfg(all(test))]
pub(crate) mod tests {
    use matrix_sdk_test::async_test;
    use ruma::{
        push::{
            PredefinedContentRuleId, PredefinedOverrideRuleId,
            PredefinedUnderrideRuleId, RuleKind, Ruleset, Action,
        },
        RoomId, UserId,
    };

    use crate::notification_settings::{ruleset_proxy::RulesetProxy, RoomNotificationMode};

    #[async_test]
    async fn get_custom_rules_for_room() {
        let room_id = RoomId::parse("!AAAaAAAAAaaAAaaaaa:matrix.org").unwrap();
        let user_id = UserId::parse("@user:matrix.org").unwrap();
        let ruleset = Ruleset::server_default(&user_id);

        let mut proxy = RulesetProxy::new(ruleset);
        assert_eq!(proxy.get_custom_rules_for_room(&room_id).len(), 0);

        // Insert an Override rule
        proxy.insert_room_rule(ruma::push::RuleKind::Override, &room_id, false).unwrap();
        assert_eq!(proxy.get_custom_rules_for_room(&room_id).len(), 1);

        // Insert a Room rule
        proxy.insert_room_rule(ruma::push::RuleKind::Room, &room_id, false).unwrap();
        assert_eq!(proxy.get_custom_rules_for_room(&room_id).len(), 2);

        // TODO: Test with a rule where the rule ID doesn't match the room id,
        // but with a condition that matches
    }

    #[async_test]
    async fn get_user_defined_room_notification_mode_none() {
        let room_id = RoomId::parse("!AAAaAAAAAaaAAaaaaa:matrix.org").unwrap();
        let user_id = UserId::parse("@user:matrix.org").unwrap();
        let ruleset = Ruleset::server_default(&user_id);
        let proxy = RulesetProxy::new(ruleset);
        let mode = proxy.get_user_defined_room_notification_mode(&room_id);
        assert!(mode.is_none());
    }

    #[async_test]
    async fn get_user_defined_room_notification_mode_mute() {
        let room_id = RoomId::parse("!AAAaAAAAAaaAAaaaaa:matrix.org").unwrap();
        let user_id = UserId::parse("@user:matrix.org").unwrap();
        let ruleset = Ruleset::server_default(&user_id);
        let mut proxy = RulesetProxy::new(ruleset);

        // Insert an Override rule that doesn't notify
        proxy.insert_room_rule(ruma::push::RuleKind::Override, &room_id, false).unwrap();
        let mode = proxy.get_user_defined_room_notification_mode(&room_id);
        assert_eq!(mode, Some(RoomNotificationMode::Mute));
    }

    #[async_test]
    async fn get_user_defined_room_notification_mode_mentions_and_keywords() {
        let room_id = RoomId::parse("!AAAaAAAAAaaAAaaaaa:matrix.org").unwrap();
        let user_id = UserId::parse("@user:matrix.org").unwrap();
        let ruleset = Ruleset::server_default(&user_id);
        let mut proxy = RulesetProxy::new(ruleset);

        // Insert a Room rule that doesn't notify
        proxy.insert_room_rule(ruma::push::RuleKind::Room, &room_id, false).unwrap();
        let mode = proxy.get_user_defined_room_notification_mode(&room_id);
        assert_eq!(mode, Some(RoomNotificationMode::MentionsAndKeywordsOnly));
    }

    #[async_test]
    async fn get_user_defined_room_notification_mode_all_messages() {
        let room_id = RoomId::parse("!AAAaAAAAAaaAAaaaaa:matrix.org").unwrap();
        let user_id = UserId::parse("@user:matrix.org").unwrap();
        let ruleset = Ruleset::server_default(&user_id);
        let mut proxy = RulesetProxy::new(ruleset);

        // Insert a Room rule that notifies
        proxy.insert_room_rule(ruma::push::RuleKind::Room, &room_id, true).unwrap();
        let mode = proxy.get_user_defined_room_notification_mode(&room_id);
        assert_eq!(mode, Some(RoomNotificationMode::AllMessages));
    }

    #[async_test]
    async fn get_predefined_underride_room_rule_id() {
        let proxy = RulesetProxy::new(Ruleset::new());

        assert_eq!(
            proxy.get_predefined_underride_room_rule_id(false, 3),
            PredefinedUnderrideRuleId::Message
        );
        assert_eq!(
            proxy.get_predefined_underride_room_rule_id(false, 2),
            PredefinedUnderrideRuleId::RoomOneToOne
        );
        assert_eq!(
            proxy.get_predefined_underride_room_rule_id(true, 3),
            PredefinedUnderrideRuleId::Encrypted
        );
        assert_eq!(
            proxy.get_predefined_underride_room_rule_id(true, 2),
            PredefinedUnderrideRuleId::EncryptedRoomOneToOne
        );
    }

    #[async_test]
    async fn get_default_room_notification_mode_mentions_and_keywords() {
        let user_id = UserId::parse("@user:matrix.org").unwrap();
        let mut ruleset = Ruleset::server_default(&user_id);
        // If the corresponding underride rule is disabled
        ruleset
            .set_enabled(RuleKind::Underride, PredefinedUnderrideRuleId::RoomOneToOne, false)
            .unwrap();

        let proxy = RulesetProxy::new(ruleset);
        let mode = proxy.get_default_room_notification_mode(false, 2);
        // Then the mode should be `MentionsAndKeywordsOnly`
        assert_eq!(mode, RoomNotificationMode::MentionsAndKeywordsOnly);
    }

    #[async_test]
    async fn get_default_room_notification_mode_all_messages() {
        let user_id = UserId::parse("@user:matrix.org").unwrap();
        let mut ruleset = Ruleset::server_default(&user_id);
        // If the corresponding underride rule is enabled
        ruleset
            .set_enabled(RuleKind::Underride, PredefinedUnderrideRuleId::RoomOneToOne, true)
            .unwrap();

        let proxy = RulesetProxy::new(ruleset);
        let mode = proxy.get_default_room_notification_mode(false, 2);
        // Then the mode should be `AllMessages`
        assert_eq!(mode, RoomNotificationMode::AllMessages);
    }

    #[async_test]
    async fn is_user_mention_enabled() {
        let user_id = UserId::parse("@user:matrix.org").unwrap();

        // If `IsUserMention` is enable, then is_user_mention_enabled() should return
        // `true`
        let mut ruleset = Ruleset::server_default(&user_id);
        ruleset
            .set_enabled(RuleKind::Override, PredefinedOverrideRuleId::IsUserMention, true)
            .unwrap();
        let proxy = RulesetProxy::new(ruleset);
        assert!(proxy.is_user_mention_enabled());

        // If `IsUserMention` is disabled, and one of the deprecated rules is enabled,
        // then is_user_mention_enabled() should return `true`
        let mut ruleset = Ruleset::server_default(&user_id);
        ruleset
            .set_enabled(RuleKind::Override, PredefinedOverrideRuleId::IsUserMention, false)
            .unwrap();
        #[allow(deprecated)]
        ruleset
            .set_enabled(RuleKind::Override, PredefinedOverrideRuleId::ContainsDisplayName, true)
            .unwrap();
        // #[allow(deprecated)]
        // ruleset.set_enabled(RuleKind::Content,
        // PredefinedContentRuleId::ContainsUserName, false).unwrap();
        let proxy = RulesetProxy::new(ruleset);
        assert!(proxy.is_user_mention_enabled());

        // If `IsUserMention` is disabled, and none of the deprecated rules is enabled,
        // then is_user_mention_enabled() should return `false`
        let mut ruleset = Ruleset::server_default(&user_id);
        ruleset
            .set_enabled(RuleKind::Override, PredefinedOverrideRuleId::IsUserMention, false)
            .unwrap();
        #[allow(deprecated)]
        ruleset
            .set_enabled(RuleKind::Override, PredefinedOverrideRuleId::ContainsDisplayName, false)
            .unwrap();
        #[allow(deprecated)]
        ruleset
            .set_enabled(RuleKind::Content, PredefinedContentRuleId::ContainsUserName, false)
            .unwrap();

        let proxy = RulesetProxy::new(ruleset);
        assert!(!proxy.is_user_mention_enabled());
    }

    #[async_test]
    async fn is_room_mention_enabled() {
        let user_id = UserId::parse("@user:matrix.org").unwrap();

        // If `IsRoomMention` is enable, then is_room_mention_enabled() should return
        // `true`
        let mut ruleset = Ruleset::server_default(&user_id);
        ruleset
            .set_enabled(RuleKind::Override, PredefinedOverrideRuleId::IsRoomMention, true)
            .unwrap();
        let proxy = RulesetProxy::new(ruleset);
        assert!(proxy.is_room_mention_enabled());

        // If `IsRoomMention` is not present, and the deprecated rules is enabled,
        // then is_room_mention_enabled() should return `true`
        let mut ruleset = Ruleset::server_default(&user_id);
        ruleset
            .set_enabled(RuleKind::Override, PredefinedOverrideRuleId::IsRoomMention, false)
            .unwrap();
        #[allow(deprecated)]
        ruleset
            .set_enabled(RuleKind::Override, PredefinedOverrideRuleId::RoomNotif, true)
            .unwrap();
        #[allow(deprecated)]
        ruleset
            .set_actions(RuleKind::Override, PredefinedOverrideRuleId::RoomNotif, vec![Action::Notify])
            .unwrap();
        let proxy = RulesetProxy::new(ruleset);
        assert!(proxy.is_room_mention_enabled());

        // If `IsRoomMention` is disabled, and the deprecated rules is disabled,
        // then is_room_mention_enabled() should return `false`
        let mut ruleset = Ruleset::server_default(&user_id);
        ruleset
            .set_enabled(RuleKind::Override, PredefinedOverrideRuleId::IsRoomMention, false)
            .unwrap();
        #[allow(deprecated)]
        ruleset
            .set_enabled(RuleKind::Override, PredefinedOverrideRuleId::RoomNotif, false)
            .unwrap();

        let proxy = RulesetProxy::new(ruleset);
        assert!(!proxy.is_room_mention_enabled());
    }

    #[async_test]
    async fn insert_room_rule() {
        let room_id = RoomId::parse("!AAAaAAAAAaaAAaaaaa:matrix.org").unwrap();
        let user_id = UserId::parse("@user:matrix.org").unwrap();
        let ruleset = Ruleset::server_default(&user_id);
        let mut proxy = RulesetProxy::new(ruleset);

        let commands = proxy.insert_room_rule(RuleKind::Override, &room_id, true).unwrap();
        assert_eq!(commands.len(), 1);
        
    }
}
