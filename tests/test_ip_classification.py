import pytest

from app.ip_classification import classify_ip


@pytest.mark.parametrize(
    ("value", "category"),
    [
        ("10.0.0.1", "private"),
        ("172.16.0.1", "private"),
        ("192.168.1.1", "private"),
        ("fc00::1", "private"),
        ("192.0.2.91", "documentation"),
        ("198.51.100.77", "documentation"),
        ("203.0.113.74", "documentation"),
        ("2001:db8::1", "documentation"),
        ("127.0.0.1", "special"),
        ("8.8.8.8", "public"),
        (None, "missing"),
        ("", "missing"),
        ("not-an-ip", "invalid"),
        (123, "invalid"),
    ],
)
def test_ip_classification_categories(value: object, category: str) -> None:
    assert classify_ip(value).category == category


def test_rfc5737_never_classifies_as_public() -> None:
    for address in ("192.0.2.91", "198.51.100.77", "203.0.113.74"):
        classification = classify_ip(address)
        assert classification.category == "documentation"
        assert classification.category != "public"
        assert classification.registry_validation_status == "not_loaded"
