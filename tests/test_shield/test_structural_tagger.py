"""
Unit tests for aegis.shield.tagger.structural — Structural Tagging.

Tests cover:
- Wrapping user messages in <user_data> tags
- Adding data isolation preamble to system message
- Creating system message when none exists
- Assistant messages not modified
- Untagging (removing tags from text)
- is_tagged check
- Multiple user messages
- Original messages not mutated
"""

from aegis.shield.tagger.structural import StructuralTagger


class TestTagging:
    """Test structural tag wrapping."""

    def test_tag_user_message(self):
        tagger = StructuralTagger()
        messages = [
            {"role": "system", "content": "You are helpful."},
            {"role": "user", "content": "My name is John."},
        ]
        result = tagger.tag(messages)

        user_content = result[1]["content"]
        assert "<user_data>" in user_content
        assert "</user_data>" in user_content
        assert "My name is John." in user_content

    def test_preamble_added_to_system(self):
        tagger = StructuralTagger()
        messages = [
            {"role": "system", "content": "Base prompt."},
            {"role": "user", "content": "Hello"},
        ]
        result = tagger.tag(messages)

        system_content = result[0]["content"]
        assert "DATA ISOLATION PROTOCOL" in system_content
        assert "Base prompt." in system_content

    def test_system_message_created_when_missing(self):
        tagger = StructuralTagger()
        messages = [
            {"role": "user", "content": "Hello"},
        ]
        result = tagger.tag(messages)

        assert result[0]["role"] == "system"
        assert "DATA ISOLATION PROTOCOL" in result[0]["content"]
        assert "<user_data>" in result[1]["content"]

    def test_assistant_messages_not_modified(self):
        tagger = StructuralTagger()
        messages = [
            {"role": "system", "content": "Base."},
            {"role": "user", "content": "Q1"},
            {"role": "assistant", "content": "A1"},
            {"role": "user", "content": "Q2"},
        ]
        result = tagger.tag(messages)

        # Assistant message should be unchanged
        assert result[2]["content"] == "A1"
        # Both user messages should be tagged
        assert "<user_data>" in result[1]["content"]
        assert "<user_data>" in result[3]["content"]

    def test_multiple_user_messages_all_tagged(self):
        tagger = StructuralTagger()
        messages = [
            {"role": "system", "content": "Base."},
            {"role": "user", "content": "First"},
            {"role": "user", "content": "Second"},
        ]
        result = tagger.tag(messages)

        for msg in result:
            if msg["role"] == "user":
                assert "<user_data>" in msg["content"]

    def test_original_messages_not_mutated(self):
        tagger = StructuralTagger()
        original = [
            {"role": "system", "content": "Original."},
            {"role": "user", "content": "Input"},
        ]
        original_system = original[0]["content"]
        original_user = original[1]["content"]

        tagger.tag(original)

        assert original[0]["content"] == original_system
        assert original[1]["content"] == original_user


class TestUntagging:
    """Test structural tag removal."""

    def test_untag_simple(self):
        tagger = StructuralTagger()
        text = "<user_data>\nHello world\n</user_data>"
        result = tagger.untag(text)
        assert result == "Hello world"

    def test_untag_no_tags(self):
        tagger = StructuralTagger()
        text = "Clean text without tags."
        result = tagger.untag(text)
        assert result == "Clean text without tags."

    def test_untag_partial_tags(self):
        tagger = StructuralTagger()
        text = "Before <user_data>content</user_data> after"
        result = tagger.untag(text)
        assert "content" in result
        assert "<user_data>" not in result


class TestIsTagged:
    """Test tag presence checking."""

    def test_tagged_text(self):
        tagger = StructuralTagger()
        assert tagger.is_tagged("<user_data>test</user_data>") is True

    def test_untagged_text(self):
        tagger = StructuralTagger()
        assert tagger.is_tagged("plain text") is False

    def test_partial_tag(self):
        tagger = StructuralTagger()
        assert tagger.is_tagged("<user_data>but no close") is False


class TestCustomTags:
    """Test custom tag configuration."""

    def test_custom_tags(self):
        tagger = StructuralTagger(
            preamble="",
            tag_open="<input>",
            tag_close="</input>",
        )
        messages = [{"role": "user", "content": "Data"}]
        result = tagger.tag(messages)
        # Find the user message (may be at index 1 if system was created)
        user_msgs = [m for m in result if m["role"] == "user"]
        assert "<input>" in user_msgs[0]["content"]
        assert "</input>" in user_msgs[0]["content"]
