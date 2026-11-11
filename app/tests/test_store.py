from pin_manager.store import _normalize_domain, get_store


def test_normalize_domain_strips_url_and_www():
    assert _normalize_domain("https://www.youtube.com/watch?v=x") == "youtube.com"
    assert _normalize_domain("HTTP://Example.COM/") == "example.com"
    assert _normalize_domain("https://www.youtube.com") == "youtube.com"
    assert _normalize_domain("www.https://www.youtube.com") == "youtube.com"


def test_blacklist_and_grants():
    store = get_store()
    store.remove_blacklist("demo.test")
    store.clear_grant("demo.test")
    store.add_blacklist("demo.test")
    assert store.is_blocked("demo.test")
    store.set_grant("demo.test", 9_999_999_999.0)
    assert not store.is_blocked("demo.test")
    assert "demo.test" not in store.blocked_domains_for_sinkhole()
    store.remove_blacklist("demo.test")
    store.add_blacklist("www-match.test")
    assert store.is_blocked("www.www-match.test")
    store.remove_blacklist("www-match.test")
