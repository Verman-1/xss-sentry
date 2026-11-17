import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from features import safe_decode, explain, indicator_features, FEATURE_NAMES

def test_url_encoding_is_peeled():
    dec, layers = safe_decode("%3Cscript%3Ealert(1)%3C%2Fscript%3E")
    assert dec == "<script>alert(1)</script>" and layers >= 1

def test_html_entity_and_unicode_layers():
    assert safe_decode("&#x3c;svg onload=alert(1)&#x3e;")[0] == "<svg onload=alert(1)>"
    assert safe_decode("\\u003cscript\\u003e")[0] == "<script>"

def test_double_encoding_is_fully_decoded():
    assert safe_decode("%253Cscript%253E")[0] == "<script>"

def test_plain_text_is_unchanged():
    assert safe_decode("how to learn python") == ("how to learn python", 0)

def test_indicators_fire_on_attack_not_on_prose():
    names = {n for n, _ in explain("<img src=x onerror=alert(1)>")}
    assert {"event_handler", "risky_tag", "dangerous_call"} <= names
    assert explain("Please alert the team about the script tomorrow") == []

def test_feature_vector_length_matches_names():
    assert len(indicator_features("<b>hi</b>")) == len(FEATURE_NAMES)
